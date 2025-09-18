# Query Tracking Authentication

## 🔒 **Security Overview**

The query tracking endpoints are now **admin-only** and require authentication to access. This ensures that only authorized administrators can view usage analytics and query data.

## 🔑 **Authentication Method**

### **Bearer Token Authentication**
All tracking endpoints require a valid admin API key in the `Authorization` header:

```bash
Authorization: Bearer <admin-api-key>
```

### **Default Admin Key**
For development/testing: `admin-tracking-key-2024`

**⚠️ IMPORTANT**: Change this key in production by setting the `ADMIN_API_KEY` environment variable.

## 📡 **Protected Endpoints**

All `/tracking/*` endpoints now require authentication:

- `GET /tracking/stats` - Usage statistics
- `GET /tracking/queries` - Query history  
- `POST /tracking/track` - Track new query
- `POST /tracking/clear` - Clear all data

## 🧪 **Testing Authentication**

### **Test Unauthorized Access (Should Fail)**
```bash
curl http://localhost:8787/tracking/stats
# Returns: 401 Unauthorized
```

### **Test Authorized Access (Should Work)**
```bash
curl -H "Authorization: Bearer admin-tracking-key-2024" \
     http://localhost:8787/tracking/stats
# Returns: JSON with usage statistics
```

### **Run Test Script**
```bash
node test-tracking.js
```

## 🚀 **Production Setup**

### **1. Set Admin API Key**
```bash
# In Cloudflare Workers dashboard or wrangler.toml
ADMIN_API_KEY=your-secure-admin-key-here
```

### **2. Use Strong Keys**
- Use a long, random string (32+ characters)
- Consider using a password manager to generate keys
- Rotate keys regularly

### **3. Environment Variables**
```bash
# Development
ADMIN_API_KEY=dev-admin-key-2024

# Production  
ADMIN_API_KEY=prod-secure-key-xyz789
```

## 🛡️ **Security Features**

### **✅ What's Protected**
- All tracking endpoints require authentication
- Admin keys are validated on every request
- Unauthorized access returns 401 status

### **✅ What's Not Affected**
- MCP tool endpoints (`/sse`) remain public
- Users can still use OpenPhone tools normally
- Only admin analytics are protected

### **✅ Privacy Preserved**
- User API keys are still hashed
- No sensitive data is stored
- Tracking is transparent to end users

## 📊 **Usage Examples**

### **Get Statistics**
```bash
curl -H "Authorization: Bearer admin-tracking-key-2024" \
     http://localhost:8787/tracking/stats
```

### **Get Query History**
```bash
curl -H "Authorization: Bearer admin-tracking-key-2024" \
     "http://localhost:8787/tracking/queries?limit=10"
```

### **Clear All Data**
```bash
curl -X POST \
     -H "Authorization: Bearer admin-tracking-key-2024" \
     http://localhost:8787/tracking/clear
```

## 🔧 **Configuration**

### **Environment Variables**
```typescript
type Env = {
  ADMIN_API_KEY?: string;  // Admin key for tracking endpoints
  // ... other variables
}
```

### **Default Behavior**
- If `ADMIN_API_KEY` is not set, uses default: `admin-tracking-key-2024`
- This allows development without additional configuration
- **Change in production!**

## 🚨 **Security Best Practices**

1. **Use Strong Keys**: 32+ character random strings
2. **Rotate Regularly**: Change admin keys periodically  
3. **Monitor Access**: Log admin key usage
4. **Limit IPs**: Consider IP whitelisting for admin access
5. **Use HTTPS**: Always use HTTPS in production

## 📝 **Error Responses**

### **401 Unauthorized**
```json
{
  "error": "Unauthorized - Admin access required",
  "status": 401
}
```

### **Missing Header**
```json
{
  "error": "Authorization header required",
  "status": 401
}
```

### **Invalid Token**
```json
{
  "error": "Invalid admin token",
  "status": 401
}
```

The authentication system ensures that only authorized administrators can access query tracking data while keeping MCP tools accessible to all users.
