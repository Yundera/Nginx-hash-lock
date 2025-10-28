const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 9999;

// Configuration from environment
const USERNAME = process.env.USER || '';
const PASSWORD = process.env.PASSWORD || '';
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS || '720', 10);
const SESSION_DURATION_MS = SESSION_DURATION_HOURS * 60 * 60 * 1000;

// In-memory session store
// Format: { sessionId: { expires: timestamp } }
const sessions = {};

// Generate secure random session ID
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// Cleanup expired sessions every hour
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [sessionId, session] of Object.entries(sessions)) {
        if (session.expires < now) {
            delete sessions[sessionId];
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Auth Service] Cleaned up ${cleaned} expired sessions`);
    }
}, 60 * 60 * 1000);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve login page
app.get('/login', (req, res) => {
    const loginHtmlPath = path.join(__dirname, '../login.html');

    if (fs.existsSync(loginHtmlPath)) {
        res.sendFile(loginHtmlPath);
    } else {
        // Fallback inline login page if file doesn't exist
        res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 3rem;
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #2c3e50; margin-bottom: 2rem; text-align: center; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; color: #2c3e50; font-weight: 500; }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 1rem;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .error { color: #e74c3c; margin-top: 1rem; text-align: center; }
        .footer {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #ecf0f1;
            color: #95a5a6;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.75rem;
        }
        .footer-logo {
            width: 120px;
            height: auto;
            opacity: 0.7;
            transition: opacity 0.3s;
        }
        .footer-logo:hover {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Login Required</h1>
        <form method="POST" action="/auth/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <input type="hidden" name="redirect" value="/">
            <button type="submit">Login</button>
            <div class="error" id="error"></div>
        </form>
        <div class="footer">
            <svg class="footer-logo" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 330.68923 161.53949"><defs><linearGradient id="d" x1="28.41308" y1="24.34637" x2="119.03571" y2="114.96899" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#27b4e1"/><stop offset=".0935" stop-color="#3da4d5"/><stop offset=".41983" stop-color="#8870ae"/><stop offset=".69027" stop-color="#bf4a92"/><stop offset=".89107" stop-color="#e13281"/><stop offset="1" stop-color="#ee2a7b"/></linearGradient></defs><g><path d="M107.81025,100.86073l6.40941.05962c16.66759,0,30.17937-13.51171,30.17937-30.1793s-13.51178-30.1793-30.17937-30.1793c-1.51561,0-3.0042.11478-4.45984.33045.06712-.86962.11199-1.74544.11199-2.63229,0-18.64504-15.1148-33.75991-33.75991-33.75991-17.83852,0-32.43546,13.83828-33.6659,31.36378-1.6969-.27143-3.43574-.41718-5.20917-.41718-18.08006,0-32.73684,14.65678-32.73684,32.73691,0,16.69318,12.57326,32.47318,28.64476,32.47318l7.71007.07145" style="fill:#dcebf9; stroke:url(#d); stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><path d="M102.9618,76.11709l-26.48454,32.23774c-1.14171,1.38972-1.7722,3.12901-1.78623,4.92752l-.24151,22.92321" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><line x1="65.9599" y1="99.84852" x2="45.93722" y2="75.47637" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><circle cx="74.44951" cy="147.53169" r="8.48961" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><rect x="90.48678" y="91.18463" width="240.20245" height="53.06293" style="fill:none;"/><path d="M109.6869,144.49847c-2.76025,0-5.23047-.58984-7.41016-1.76953-2.18066-1.17969-3.8999-2.91016-5.16016-5.19043-1.25977-2.27979-1.88965-5.0791-1.88965-8.3999v-14.75977c0-.87939.28955-1.60986.86963-2.18994.57959-.57959,1.31006-.87012,2.18994-.87012.87939,0,1.60986.29053,2.19043.87012.5791.58008.86963,1.31055.86963,2.18994v14.75977c0,2.24072.41992,4.09033,1.26025,5.55029.83984,1.46045,1.97998,2.54053,3.41992,3.23975,1.43994.7002,3.06006,1.0498,4.85986,1.0498,1.71924,0,3.24951-.33936,4.59033-1.02002,1.33936-.67969,2.40918-1.59912,3.20996-2.75977.79932-1.15967,1.19971-2.45996,1.19971-3.8999h3.78027c0,2.48047-.61035,4.72021-1.83008,6.71973-1.2207,2.00098-2.87988,3.58057-4.97998,4.73975-2.1001,1.16113-4.49072,1.74023-7.16992,1.74023ZM122.94667,144.19867c-.88037,0-1.61035-.29004-2.18994-.87012-.58057-.5791-.87012-1.30957-.87012-2.18945v-26.76025c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.76025c0,.87988-.28027,1.61035-.83984,2.18945-.56104.58008-1.30029.87012-2.22021.87012Z" style="fill:#294056;"/><path d="M139.8661,144.25824c-.88037,0-1.61035-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-26.75977c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.75977c0,.87988-.28027,1.61035-.83984,2.19043-.56104.58008-1.30029.86914-2.22021.86914ZM164.52626,144.25824c-.88037,0-1.61084-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-14.75977c0-2.28027-.41992-4.14014-1.26025-5.58008-.83984-1.43994-1.97021-2.50977-3.38965-3.20996-1.42041-.69971-3.05078-1.05029-4.89014-1.05029-1.68018,0-3.20068.34033-4.56006,1.02002-1.36035.68066-2.44043,1.58984-3.23975,2.72998-.80078,1.14014-1.2002,2.45068-1.2002,3.93018h-3.77979c0-2.52002.60938-4.77002,1.82959-6.75,1.21973-1.97998,2.88965-3.54932,5.01025-4.70996,2.11963-1.15967,4.5-1.74023,7.14014-1.74023,2.75977,0,5.229.59082,7.40967,1.77002,2.17969,1.18018,3.8999,2.91016,5.16016,5.18994,1.25977,2.28027,1.89014,5.08057,1.89014,8.40039v14.75977c0,.87988-.29102,1.61035-.87012,2.19043-.58057.58008-1.31055.86914-2.18994.86914Z" style="fill:#294056;"/><path d="M192.60633,144.4389c-3.12012,0-5.93066-.72949-8.43066-2.19043-2.5-1.45947-4.47949-3.44971-5.93945-5.96973-1.46094-2.52002-2.19043-5.35986-2.19043-8.52002,0-3.15967.66992-5.98975,2.01074-8.49023,1.33887-2.49902,3.16895-4.479,5.48926-5.93994,2.31934-1.45947,4.94043-2.18994,7.86035-2.18994,2.35938,0,4.53906.49023,6.54004,1.47021,2,.98047,3.67969,2.31006,5.04004,3.98975v-16.19971c0-.91992.28906-1.65967.87012-2.22021.5791-.55957,1.30957-.83984,2.18945-.83984.91992,0,1.65918.28027,2.2207.83984.55957.56055.83984,1.30029.83984,2.22021v27.35986c0,3.16016-.73047,6-2.19043,8.52002-1.46094,2.52002-3.42969,4.51025-5.91016,5.96973-2.48047,1.46094-5.2793,2.19043-8.39941,2.19043ZM192.60633,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.32959,3.7793-4.05029.91992-1.71924,1.38086-3.63916,1.38086-5.75977,0-2.16016-.46094-4.08008-1.38086-5.76025-.91992-1.67969-2.17969-3.00928-3.7793-3.98975-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.31006-3.83984,3.98975-.94043,1.68018-1.41016,3.6001-1.41016,5.76025,0,2.12061.46973,4.04053,1.41016,5.75977.93945,1.7207,2.2207,3.07031,3.83984,4.05029,1.62012.98047,3.42969,1.46973,5.43066,1.46973Z" style="fill:#294056;"/><path d="M235.32606,144.4389c-3.32129,0-6.27051-.70996-8.85059-2.12988s-4.59961-3.37988-6.05957-5.88037c-1.46094-2.49951-2.19043-5.37012-2.19043-8.60986,0-3.2793.69043-6.16992,2.07031-8.66992,1.37988-2.49951,3.29004-4.45996,5.72949-5.88037,2.43945-1.41943,5.24023-2.12988,8.40039-2.12988,3.12012,0,5.7998.68994,8.04004,2.06982,2.23926,1.38037,3.9502,3.28076,5.12988,5.7002,1.17969,2.4209,1.77051,5.21045,1.77051,8.37012,0,.76025-.26074,1.39014-.78027,1.89014-.52051.50049-1.18066.75-1.98047.75h-24.17969v-4.80029h24l-2.45996,1.68018c-.04004-2-.44043-3.78955-1.2002-5.37012-.75977-1.57959-1.83984-2.82959-3.24023-3.75-1.40039-.91943-3.09961-1.37988-5.09961-1.37988-2.28027,0-4.22949.50049-5.84961,1.5-1.62012,1-2.85059,2.37012-3.69043,4.10986-.83984,1.74023-1.25977,3.71045-1.25977,5.91016,0,2.2002.5,4.16064,1.5,5.87988.99902,1.72021,2.37891,3.08057,4.13965,4.08008,1.75977,1,3.78027,1.5,6.06055,1.5,1.23926,0,2.50977-.22998,3.80957-.68994,1.2998-.45947,2.34961-.99023,3.15039-1.59033.59961-.43945,1.24902-.66895,1.9502-.68994.69922-.01953,1.30957.19043,1.8291.63037.67969.59961,1.04004,1.25977,1.08008,1.97998.04004.71973-.28027,1.34033-.95996,1.85986-1.36035,1.08008-3.05078,1.95996-5.06934,2.63965-2.02051.68066-3.95117,1.02051-5.79004,1.02051Z" style="fill:#294056;"/><path d="M260.16493,144.19867c-.95996,0-1.70117-.24902-2.2207-.75-.51953-.5-.7793-1.25-.7793-2.25v-26.81982c0-.95996.25977-1.69971.7793-2.22021.51953-.51953,1.26074-.77979,2.2207-.77979.99902,0,1.74902.25,2.25.75.49902.50049.75,1.25049.75,2.25v26.81982c0,.95996-.25098,1.7002-.75,2.21973-.50098.52051-1.25098.78027-2.25.78027ZM260.10438,123.67865c0-2.3999.58984-4.5498,1.77051-6.4502,1.17871-1.89893,2.76855-3.40967,4.76953-4.52979,2-1.11914,4.2002-1.68018,6.60059-1.68018,2.39941,0,4.18945.39014,5.36914,1.17041,1.17969.77979,1.62988,1.70996,1.35059,2.78955-.12012.56104-.35059.99023-.69043,1.29004-.33984.30029-.73047.49072-1.16992.57031-.44043.08057-.9209.06006-1.43945-.06006-2.56055-.51953-4.86035-.55957-6.90039-.12012-2.04004.44043-3.65039,1.26025-4.83008,2.45996-1.18066,1.2002-1.76953,2.7207-1.76953,4.56006h-3.06055Z" style="fill:#294056;"/><path d="M297.60438,144.4389c-2.91992,0-5.54102-.72949-7.86035-2.19043-2.32031-1.45947-4.15039-3.43945-5.48926-5.93994-1.34082-2.49902-2.01074-5.32959-2.01074-8.48975,0-3.15967.72949-6,2.19043-8.52002,1.45996-2.52002,3.43945-4.50928,5.93945-5.97021,2.5-1.45947,5.31055-2.18994,8.43066-2.18994s5.91895.73047,8.39941,2.18994c2.48047,1.46094,4.44922,3.4502,5.91016,5.97021,1.45996,2.52002,2.19043,5.36035,2.19043,8.52002h-2.33984c0,3.16016-.6709,5.99072-2.01074,8.48975-1.33984,2.50049-3.16992,4.48047-5.48926,5.93994-2.32031,1.46094-4.94141,2.19043-7.86035,2.19043ZM298.80458,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.31934,3.7793-4.02002.91992-1.69971,1.38086-3.60938,1.38086-5.72998,0-2.16016-.46094-4.08936-1.38086-5.79004-.91992-1.69971-2.17969-3.03955-3.7793-4.02002-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.32031-3.83984,4.02002-.94043,1.70068-1.41016,3.62988-1.41016,5.79004,0,2.12061.46973,4.03027,1.41016,5.72998.93945,1.70068,2.2207,3.04004,3.83984,4.02002,1.62012.98047,3.42969,1.46973,5.43066,1.46973ZM312.24403,144.25824c-.87988,0-1.61035-.28906-2.18945-.86914-.58105-.58008-.87012-1.31055-.87012-2.19043v-9.18018l1.13965-6.35986,4.98047,2.16016v13.37988c0,.87988-.29102,1.61035-.87012,2.19043-.58008.58008-1.31055.86914-2.19043.86914Z" style="fill:#294056;"/></g></svg>
            <div>Protected by Nginx Hash Lock - Credential-Based Authentication</div>
        </div>
    </div>
    <script>
        const params = new URLSearchParams(window.location.search);
        if (params.get('error') === 'invalid') {
            document.getElementById('error').textContent = 'Invalid username or password';
        }
        if (params.get('redirect')) {
            document.querySelector('input[name="redirect"]').value = params.get('redirect');
        }
    </script>
</body>
</html>
        `);
    }
});

// Handle login submission
app.post('/auth/login', async (req, res) => {
    const { username, password, redirect } = req.body;
    const startTime = Date.now();

    // Validate credentials
    const isValid = username === USERNAME && password === PASSWORD;

    if (isValid) {
        // Create session
        const sessionId = generateSessionId();
        sessions[sessionId] = {
            expires: Date.now() + SESSION_DURATION_MS
        };

        console.log(`[Auth Service] Login successful for user: ${username}`);
        console.log(`[Auth Service] Session created: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

        // Set cookie and redirect
        res.cookie('nginxhashlock_session', sessionId, {
            httpOnly: true,
            secure: false, // Set to true if using HTTPS
            maxAge: SESSION_DURATION_MS,
            sameSite: 'lax'
        });

        res.redirect(redirect || '/');
    } else {
        // Apply 2-second delay for failed attempts (anti-brute force)
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, 2000 - elapsed);

        console.log(`[Auth Service] Login failed for user: ${username || '(empty)'}`);

        setTimeout(() => {
            res.redirect('/login?error=invalid' + (redirect ? `&redirect=${encodeURIComponent(redirect)}` : ''));
        }, delay);
    }
});

// Auth check endpoint (called by nginx auth_request)
app.get('/auth/check', (req, res) => {
    // Check for existing session first
    let sessionId = req.cookies.nginxhashlock_session;

    if (sessionId && sessions[sessionId] && sessions[sessionId].expires > Date.now()) {
        // Valid session exists
        console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
        return res.status(200).send('OK');
    }

    // No valid session - check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const originalUri = req.headers['x-original-uri'] || '';
        const hashMatch = originalUri.match(/[?&]hash=([^&]+)/);

        if (hashMatch && hashMatch[1] === process.env.AUTH_HASH) {
            console.log('[Auth Service] Auth check passed via hash parameter');

            // Create a new session only if one doesn't exist
            if (!sessionId || !sessions[sessionId]) {
                sessionId = generateSessionId();
                sessions[sessionId] = {
                    expires: Date.now() + SESSION_DURATION_MS
                };

                console.log(`[Auth Service] Session created for hash auth: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

                // Set session cookie
                res.cookie('nginxhashlock_session', sessionId, {
                    httpOnly: true,
                    secure: false,
                    maxAge: SESSION_DURATION_MS,
                    sameSite: 'lax'
                });
            }

            return res.status(200).send('OK');
        }
    }

    // Check session cookie again (for cases where hash auth wasn't valid)
    sessionId = req.cookies.nginxhashlock_session;

    if (!sessionId) {
        console.log('[Auth Service] Auth check failed: No session cookie and no valid hash');
        return res.status(401).send('Unauthorized');
    }

    const session = sessions[sessionId];

    if (!session) {
        console.log(`[Auth Service] Auth check failed: Session not found (${sessionId.substring(0, 8)}...)`);
        return res.status(401).send('Unauthorized');
    }

    if (session.expires < Date.now()) {
        console.log(`[Auth Service] Auth check failed: Session expired (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return res.status(401).send('Unauthorized');
    }

    // Session is valid
    console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
    res.status(200).send('OK');
});

// Establish session endpoint (for hash authentication to set cookies properly)
app.get('/auth/establish-session', (req, res) => {
    // Check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const hash = req.query.hash;
        const returnTo = req.query.return_to || '/';

        if (hash && hash === process.env.AUTH_HASH) {
            // Check if session already exists
            let sessionId = req.cookies.nginxhashlock_session;

            if (sessionId && sessions[sessionId] && sessions[sessionId].expires > Date.now()) {
                // Valid session already exists
                console.log(`[Auth Service] Session already valid: ${sessionId.substring(0, 8)}...`);
                // Redirect back if requested
                if (req.query.return_to) {
                    return res.redirect(returnTo);
                }
                return res.status(200).json({ status: 'ok', message: 'Session already valid' });
            }

            // Create new session
            sessionId = generateSessionId();
            sessions[sessionId] = {
                expires: Date.now() + SESSION_DURATION_MS
            };

            console.log(`[Auth Service] Session established via hash: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

            // Set session cookie
            res.cookie('nginxhashlock_session', sessionId, {
                httpOnly: true,
                secure: false,
                maxAge: SESSION_DURATION_MS,
                sameSite: 'lax'
            });

            // Redirect back if requested
            if (req.query.return_to) {
                return res.redirect(returnTo);
            }

            return res.status(200).json({ status: 'ok', message: 'Session established' });
        }
    }

    return res.status(401).json({ status: 'error', message: 'Invalid or missing hash' });
});

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        activeSessions: Object.keys(sessions).length,
        sessionDurationHours: SESSION_DURATION_HOURS
    });
});

// Start server
app.listen(PORT, () => {
    console.log('=====================================');
    console.log('[Auth Service] Started successfully');
    console.log(`[Auth Service] Listening on port ${PORT}`);
    console.log(`[Auth Service] Username configured: ${USERNAME ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] Password configured: ${PASSWORD ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] Session duration: ${SESSION_DURATION_HOURS} hours`);
    console.log('=====================================');
});
