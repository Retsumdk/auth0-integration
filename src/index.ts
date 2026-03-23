import { Request, Response, NextFunction, RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';

export interface Auth0Config {
  domain: string;
  audience: string;
  clientId: string;
  clientSecret: string;
}

export interface AuthUser {
  sub: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  token: string;
}

export interface AuthRequest extends Request {
  auth?: AuthUser;
}

export class Auth0Client {
  private config: Auth0Config;
  private jwksClient: jwksRsa.JwksClient;

  constructor(config: Auth0Config) {
    this.config = config;
    this.jwksClient = jwksRsa({
      jwksUri: `https://${config.domain}/.well-known/jwks.json`,
      cache: true,
      cacheMaxAge: 600000,
    });
  }

  private async getSigningKey(kid: string): Promise<string> {
    const key = await this.jwksClient.getSigningKey(kid);
    return key.getPublicKey();
  }

  async validateToken(token: string): Promise<AuthUser> {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid token');
    }

    const kid = decoded.header.kid;
    if (!kid) {
      throw new Error('Token missing key ID');
    }

    const signingKey = await this.getSigningKey(kid);

    const payload = jwt.verify(token, signingKey, {
      audience: this.config.audience,
      issuer: `https://${this.config.domain}/`,
      algorithms: ['RS256'],
    }) as Record<string, unknown>;

    return {
      sub: payload.sub as string,
      email: payload.email as string | undefined,
      roles: payload['https://example.com/roles'] as string[] | undefined,
      permissions: payload.permissions as string[] | undefined,
      token,
    };
  }

  async getUser(userId: string): Promise<Record<string, unknown>> {
    const response = await fetch(`https://${this.config.domain}/api/v2/users/${userId}`, {
      headers: {
        Authorization: `Bearer ${await this.getManagementToken()}`,
      },
    });
    return response.json();
  }

  private async getManagementToken(): Promise<string> {
    const response = await fetch(`https://${this.config.domain}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        audience: `https://${this.config.domain}/api/v2/`,
      }),
    });
    const data = await response.json();
    return data.access_token;
  }

  async getRoles(userId: string): Promise<string[]> {
    const response = await fetch(
      `https://${this.config.domain}/api/v2/users/${userId}/roles`,
      {
        headers: {
          Authorization: `Bearer ${await this.getManagementToken()}`,
        },
      }
    );
    const roles = await response.json();
    return roles.map((r: { name: string }) => r.name);
  }
}

export function createAuthMiddleware(auth0: Auth0Client): RequestHandler {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.slice(7);
    try {
      const user = await auth0.validateToken(token);
      req.auth = user;
      next();
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

type RoleRequirement = string | string[];

export function requireRole(roles: RoleRequirement): RequestHandler {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    const userRoles = req.auth.roles || [];

    const hasRole = requiredRoles.some((role) => userRoles.includes(role));
    if (!hasRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

export function requirePermission(permissions: string | string[]): RequestHandler {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const requiredPermissions = Array.isArray(permissions)
      ? permissions
      : [permissions];
    const userPermissions = req.auth.permissions || [];

    const hasPermission = requiredPermissions.some((perm) =>
      userPermissions.includes(perm)
    );
    if (!hasPermission) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

export async function getUserRoles(
  auth0: Auth0Client,
  token: string
): Promise<string[]> {
  const user = await auth0.validateToken(token);
  if (!user.sub) {
    return [];
  }
  return auth0.getRoles(user.sub);
}
