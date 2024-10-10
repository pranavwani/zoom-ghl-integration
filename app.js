const express = require('express');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Secret token from Zoom webhook settings
const webhookSecretToken = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;

// Load tokens from tokens.json
function loadTokens() {
    const data = fs.readFileSync('tokens.json');
    return JSON.parse(data);
}

// Save tokens to tokens.json
function saveTokens(tokens) {
    fs.writeFileSync('tokens.json', JSON.stringify(tokens, null, 2));
}

// Route to handle Zoom OAuth redirect and generate tokens
app.get('/generate-token', async (req, res) => {
    const authCode = req.query.code; // Get the authorization code from the query string

    if (!authCode) {
        return res.status(400).send('Authorization code is missing');
    }

    try {
        // Exchange authorization code for access token
        const tokenResponse = await axios.post(
            'https://zoom.us/oauth/token',
            null,
            {
                params: {
                    grant_type: 'authorization_code',
                    code: authCode,
                    redirect_uri: 'http://localhost:3000/generate-token', // Redirect URI
                },
                auth: {
                    username: process.env.ZOOM_CLIENT_ID, // Client ID
                    password: process.env.ZOOM_CLIENT_SECRET, // Client Secret
                },
            }
        );

        // Get access and refresh tokens from the response
        const { access_token, refresh_token } = tokenResponse.data;

        // Save the tokens to tokens.json
        saveTokens({ access_token, refresh_token });

        res.send(`
        <h1>Zoom OAuth Token Generated</h1>
        <p>Access Token: ${access_token}</p>
        <p>Refresh Token: ${refresh_token}</p>
      `);
    } catch (error) {
        console.error(
            'Error exchanging authorization code for tokens:',
            error.response ? error.response.data : error.message
        );
        res.status(500).send('Error generating tokens');
    }
});

// Function to get Zoom Phone call logs using OAuth token
async function getZoomCallLogs() {
    const tokens = loadTokens(); // Load the current access token
    try {
        const response = await axios.get(
            `${process.env.ZOOM_API_BASE_URL}/phone/call_logs`,
            {
                headers: {
                    Authorization: `Bearer ${tokens.access_token}`, // Use dynamic access token
                },
            }
        );

        return response.data;
    } catch (error) {
        console.error(
            'Error fetching Zoom call logs:',
            error.response ? error.response.data : error.message
        );

        // If token expired, try refreshing it
        if (error.response && error.response.status === 401) {
            await refreshZoomToken(tokens.refresh_token); // Refresh the token if expired
            return getZoomCallLogs(); // Retry the request with the new token
        } else {
            throw error;
        }
    }
}

// Function to log call details into GoHighLevel (GHL)
async function logCallToGHL(callDetails) {
    try {
        const response = await axios.post(
            `${process.env.GHL_API_BASE_URL}/calls`,
            callDetails,
            {
                headers: {
                    Authorization: `Bearer ${process.env.GHL_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        console.log('Successfully logged call in GHL:', response.data);
        return response.data;
    } catch (error) {
        console.error(
            'Error logging call to GHL:',
            error.response ? error.response.data : error.message
        );
        throw error;
    }
}

// Route to handle Zoom webhooks
app.post('/webhook/zoom', async (req, res) => {
    try {
        console.log('Zoom webhook received:', req.body);

        const eventData = req.body;

        // Handle Zoom URL validation
        if (eventData.event === 'endpoint.url_validation') {
            const plainToken = eventData.payload.plainToken;

            // Create HMAC SHA-256 hash using webhookSecretToken as the key and plainToken as the message
            const hmac = crypto.createHmac('sha256', webhookSecretToken);
            hmac.update(plainToken);
            const encryptedToken = hmac.digest('hex'); // Output in hex format

            // Respond with the plainToken and encryptedToken
            return res.json({
                plainToken: plainToken,
                encryptedToken: encryptedToken,
            });
        }

        if (
            eventData.event === 'phone.callee_made_call' ||
            eventData.event === 'phone.callee_received_call'
        ) {
            const callDetails = {
                caller: eventData.payload.object.caller.caller_name,
                callee: eventData.payload.object.callee.callee_name,
                call_duration: eventData.payload.object.duration,
                call_time: eventData.payload.object.start_time,
                recording_url: eventData.payload.object.recording
                    ? eventData.payload.object.recording.download_url
                    : null,
            };

            await logCallToGHL(callDetails);
        }

        res.status(200).send('Event received');
    } catch (error) {
        console.error('Error processing Zoom webhook:', error.message);
        res.status(500).send('Error processing event');
    }
});

// Function to refresh the Zoom OAuth token
async function refreshZoomToken(refreshToken) {
    try {
        const tokenResponse = await axios.post(
            'https://zoom.us/oauth/token',
            null,
            {
                params: {
                    grant_type: 'refresh_token',
                    refresh_token: refreshToken,
                },
                auth: {
                    username: process.env.ZOOM_CLIENT_ID,
                    password: process.env.ZOOM_CLIENT_SECRET,
                },
            }
        );

        const { access_token, refresh_token: newRefreshToken } =
            tokenResponse.data;

        // Save the new tokens to tokens.json
        const updatedTokens = {
            access_token,
            refresh_token: newRefreshToken,
        };
        saveTokens(updatedTokens);

        console.log('Zoom OAuth token refreshed successfully.');
    } catch (error) {
        console.error(
            'Error refreshing Zoom OAuth token:',
            error.response ? error.response.data : error.message
        );
        throw error;
    }
}

// Route to trigger syncing calls manually (fetch call logs and sync with GHL)
app.get('/sync-calls', async (req, res) => {
    try {
        const zoomLogs = await getZoomCallLogs();

        for (const log of zoomLogs.call_logs) {
            const callDetails = {
                caller: log.caller_name,
                callee: log.callee_name,
                call_duration: log.duration,
                call_time: log.start_time,
                recording_url: log.recording
                    ? log.recording.download_url
                    : null,
            };

            await logCallToGHL(callDetails);
        }

        res.json({ message: 'Call logs successfully synced!' });
    } catch (error) {
        res.status(500).json({
            message: 'Error syncing call logs',
            error: error.message,
        });
    }
});

// Validate incoming requests
app.get('/', (req, res) => {
    res.send('Zoom API Integration with Node.js');
});

// Validate incoming requests
app.post('/', (req, res) => {
    res.send('Zoom API Integration with Node.js');
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
