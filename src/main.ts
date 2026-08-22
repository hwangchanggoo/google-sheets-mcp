#!/usr/bin/env node
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, {type NextFunction, type Request, type Response} from 'express';
import {createServer} from './index.js';
import type {
	OAuthMetadata, OAuthProtectedResourceMetadata, OAuthClientInformationFull, OAuthClientMetadata,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import {isTokenValid} from './utils/token-cache.js';

// Google OAuth configuration - users must provide their own credentials
const {GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET} = process.env;

const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

const SHEETS_SCOPES = [
	'https://www.googleapis.com/auth/spreadsheets',
];

function setupSignalHandlers(cleanup: () => Promise<void>): void {
	process.on('SIGINT', async () => {
		await cleanup();
		process.exit(0);
	});
	process.on('SIGTERM', async () => {
		await cleanup();
		process.exit(0);
	});
}

function extractBearerToken(req: Request): string | undefined {
	const authHeader = req.headers.authorization;
	if (!authHeader?.startsWith('Bearer ')) {
		return undefined;
	}

	return authHeader.slice(7);
}

const transport = process.env.MCP_TRANSPORT || 'stdio';

(async () => {
	if (transport === 'stdio') {
		const accessToken = process.env.GOOGLE_ACCESS_TOKEN;
		if (!accessToken) {
			console.error('google-sheets-mcp: GOOGLE_ACCESS_TOKEN required for stdio transport');
			console.error('For OAuth support, use HTTP transport: MCP_TRANSPORT=http');

			process.exit(1);
		}

		const server = createServer({token: accessToken});
		setupSignalHandlers(async () => server.close());

		const stdioTransport = new StdioServerTransport();
		await server.connect(stdioTransport);
		console.error('Google Sheets MCP server running on stdio');
	} else if (transport === 'http') {
		if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
			console.error('google-sheets-mcp: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET required for HTTP transport');

			process.exit(1);
		}

		const app = express();

		// Remote and browser-based MCP clients preflight every request, and need to
		// read Mcp-Session-Id and WWW-Authenticate off the response to drive the
		// session and OAuth flows. Without this the connection fails before any
		// JSON-RPC is exchanged.
		app.use((req: Request, res: Response, next: NextFunction) => {
			res.setHeader('Access-Control-Allow-Origin', req.headers.origin ?? '*');
			res.setHeader('Vary', 'Origin');
			res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
			res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID');
			res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id, WWW-Authenticate');
			res.setHeader('Access-Control-Max-Age', '86400');
			if (req.method === 'OPTIONS') {
				res.sendStatus(204);
				return;
			}

			next();
		});

		app.use(express.json({limit: '20mb'}));
		app.use(express.urlencoded({extended: true}));

		const port = parseInt(process.env.PORT || '3000', 10);
		const baseUrl = process.env.MCP_BASE_URL || `http://localhost:${port}`;

		// OAuth Authorization Server Metadata (RFC 8414)
		// We act as the authorization server, proxying to Google
		const oauthMetadata: OAuthMetadata = {
			issuer: baseUrl,
			authorization_endpoint: `${baseUrl}/authorize`,
			token_endpoint: `${baseUrl}/token`,
			registration_endpoint: `${baseUrl}/register`,
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			code_challenge_methods_supported: ['S256'],
			scopes_supported: SHEETS_SCOPES,
		};

		// Protected Resource Metadata (RFC 9728)
		const protectedResourceMetadata: OAuthProtectedResourceMetadata = {
			resource: `${baseUrl}/mcp`,
			authorization_servers: [baseUrl],
			scopes_supported: SHEETS_SCOPES,
			resource_name: 'Google Sheets MCP Server',
			resource_documentation: 'https://github.com/domdomegg/google-sheets-mcp',
		};

		// RFC 9728: a 401 must tell the client where to find the metadata above,
		// otherwise it cannot discover that this is an MCP server needing OAuth.
		const wwwAuthenticate = `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`;

		// Metadata endpoints
		app.get('/.well-known/oauth-authorization-server', (_req, res) => {
			res.json(oauthMetadata);
		});
		app.get('/.well-known/oauth-protected-resource', (_req, res) => {
			res.json(protectedResourceMetadata);
		});
		app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
			res.json(protectedResourceMetadata);
		});

		// Dynamic Client Registration endpoint
		// We proxy through our /callback so any redirect URI works
		// Client ID/secret don't matter - we inject the real ones when proxying
		app.post('/register', (req: Request<object, object, OAuthClientMetadata>, res) => {
			const response: OAuthClientInformationFull = {
				...req.body,
				client_id: 'google-sheets-mcp',
				client_id_issued_at: Math.floor(Date.now() / 1000),
			};
			res.status(201).json(response);
		});

		// Authorization endpoint - redirect to Google
		// We encode the client's redirect_uri in state so we can forward the code back
		app.get('/authorize', (req: Request, res: Response) => {
			const clientRedirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : '';
			const clientState = typeof req.query.state === 'string' ? req.query.state : '';
			const codeChallenge = typeof req.query.code_challenge === 'string' ? req.query.code_challenge : '';
			const codeChallengeMethod = typeof req.query.code_challenge_method === 'string' ? req.query.code_challenge_method : 'S256';

			// Encode client's redirect_uri and state in our state parameter
			const wrappedState = Buffer.from(JSON.stringify({
				redirect_uri: clientRedirectUri,
				state: clientState,
			})).toString('base64url');

			const params = new URLSearchParams({
				client_id: GOOGLE_CLIENT_ID,
				redirect_uri: `${baseUrl}/callback`,
				response_type: 'code',
				scope: SHEETS_SCOPES.join(' '),
				access_type: 'offline',
				prompt: 'consent',
				state: wrappedState,
				code_challenge: codeChallenge,
				code_challenge_method: codeChallengeMethod,
			});

			res.redirect(`${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`);
		});

		// Callback endpoint - receives code from Google and forwards to client
		app.get('/callback', (req: Request, res: Response) => {
			const code = typeof req.query.code === 'string' ? req.query.code : '';
			const wrappedState = typeof req.query.state === 'string' ? req.query.state : '';
			const error = typeof req.query.error === 'string' ? req.query.error : '';

			try {
				const {redirect_uri: clientRedirectUri, state: clientState} = JSON.parse(Buffer.from(wrappedState, 'base64url').toString()) as {redirect_uri: string; state: string};

				const params = new URLSearchParams();
				if (code) {
					params.set('code', code);
				}

				if (clientState) {
					params.set('state', clientState);
				}

				if (error) {
					params.set('error', error);
				}

				res.redirect(`${clientRedirectUri}?${params.toString()}`);
			} catch {
				res.status(400).json({error: 'invalid_state', error_description: 'Could not decode state parameter'});
			}
		});

		// Token endpoint - proxy to Google, injecting our client credentials
		app.post('/token', async (req: Request, res: Response) => {
			try {
				const body = new URLSearchParams({
					...req.body,
					client_id: GOOGLE_CLIENT_ID,
					client_secret: GOOGLE_CLIENT_SECRET,
					redirect_uri: `${baseUrl}/callback`,
				});

				const response = await fetch(GOOGLE_TOKEN_ENDPOINT, {
					method: 'POST',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: body.toString(),
				});

				const data = await response.json();
				res.status(response.status).json(data);
			} catch (error) {
				console.error('Token exchange error:', error);
				res.status(500).json({error: 'server_error', error_description: 'Token exchange failed'});
			}
		});

		// Clients probe GET (SSE stream) and DELETE (session teardown) on the MCP
		// endpoint. This transport is stateless so neither applies, but falling
		// through to Express's 404 reads as "wrong URL" rather than "wrong method".
		const methodNotAllowed = (_req: Request, res: Response) => {
			res.setHeader('Allow', 'POST, OPTIONS');
			res.status(405).json({
				jsonrpc: '2.0',
				error: {code: -32000, message: 'Method Not Allowed: this server is stateless, use POST'},
				id: null,
			});
		};

		app.get('/mcp', methodNotAllowed);
		app.delete('/mcp', methodNotAllowed);

		// Stateless MCP endpoint
		app.post('/mcp', async (req: Request, res: Response) => {
			const token = extractBearerToken(req);

			// Require auth, except for tools/list for discovery
			const method = req.body?.method as string | undefined;
			if (!token && method !== 'tools/list') {
				res.setHeader('WWW-Authenticate', wwwAuthenticate);
				res.status(401).json({
					jsonrpc: '2.0',
					error: {code: -32001, message: 'Unauthorized: Bearer token required'},
					id: null,
				});
				return;
			}

			// Validate token before processing
			if (token && !await isTokenValid(token)) {
				res.setHeader('WWW-Authenticate', wwwAuthenticate);
				res.status(401).json({
					jsonrpc: '2.0',
					error: {code: -32001, message: 'Unauthorized: Invalid or expired token'},
					id: null,
				});
				return;
			}

			const server = createServer({token: token ?? ''});

			try {
				const httpTransport = new StreamableHTTPServerTransport({
					sessionIdGenerator: undefined,
					enableJsonResponse: true,
				});
				await server.connect(httpTransport);
				await httpTransport.handleRequest(req, res, req.body);

				res.on('close', () => {
					void httpTransport.close();
					void server.close();
				});
			} catch (error) {
				console.error('Error handling MCP request:', error);
				if (!res.headersSent) {
					res.status(500).json({
						jsonrpc: '2.0',
						error: {code: -32603, message: 'Internal server error'},
						id: null,
					});
				}
			}
		});

		const httpServer = app.listen(port, () => {
			console.error(`Google Sheets MCP server running on ${baseUrl}/mcp`);
		});

		httpServer.on('error', (err: NodeJS.ErrnoException) => {
			console.error('FATAL: Server error', err.message);
			process.exit(1);
		});

		setupSignalHandlers(async () => {
			httpServer.close();
		});
	} else {
		console.error(`Unknown transport: ${transport}. Use MCP_TRANSPORT=stdio or MCP_TRANSPORT=http`);

		process.exit(1);
	}
})();
