# Auth0 Integration

TypeScript SDK for integrating Auth0 into Node.js applications with role-based access control (RBAC).

## Features

- Easy Auth0 authentication integration
- Role-based access control (RBAC) middleware
- JWT token validation and verification
- User role management helpers
- Express.js middleware included

## Installation

```bash
npm install auth0-integration
# or
bun add auth0-integration
```

## Configuration

Create a `.env` file:

```env
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://your-api.example.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
```

## Usage

### Basic Setup

```typescript
import { Auth0Client, createAuthMiddleware } from 'auth0-integration';
import express from 'express';

const app = express();

// Initialize Auth0 client
const auth0 = new Auth0Client({
  domain: process.env.AUTH0_DOMAIN!,
  audience: process.env.AUTH0_AUDIENCE!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
});

// Add authentication middleware
app.use(createAuthMiddleware(auth0));

// Protected route
app.get('/api/protected', (req, res) => {
  res.json({ 
    message: 'Access granted',
    user: req.auth?.user 
  });
});

app.listen(3000);
```

### RBAC Middleware

```typescript
import { requireRole } from 'auth0-integration';

// Require specific role
app.get('/admin', requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin area' });
});

// Require any of multiple roles
app.get('/moderator', requireRole(['admin', 'moderator']), (req, res) => {
  res.json({ message: 'Moderator area' });
});
```

### Get User Roles

```typescript
import { getUserRoles } from 'auth0-integration';

app.get('/my-roles', async (req, res) => {
  const token = req.auth?.token;
  if (!token) return res.status(401).json({ error: 'No token' });
  
  const roles = await getUserRoles(auth0, token);
  res.json({ roles });
});
```

## API Reference

### Auth0Client

| Method | Description |
|--------|-------------|
| `validateToken(token)` | Validate and decode a JWT token |
| `getUser(userId)` | Fetch user info from Auth0 |
| `getRoles(userId)` | Get roles for a specific user |

### Middleware

| Function | Description |
|----------|-------------|
| `createAuthMiddleware(client)` | Express middleware for JWT validation |
| `requireRole(roles)` | Middleware to require specific roles |
| `requirePermission(permissions)` | Middleware to require permissions |

## License

MIT
