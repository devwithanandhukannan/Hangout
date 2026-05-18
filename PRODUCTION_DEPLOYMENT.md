# 🚀 Production Deployment Guide - Hangout Application

**Status:** ✅ Production Ready  
**Last Updated:** May 19, 2026  
**Deployment:** Vercel (Frontend) + Render (Backend)

---

## Overview

Your Hangout application is configured for production deployment with:
- **Frontend**: Vercel (https://hangout-one-chi.vercel.app)
- **Backend**: Render (https://hangout-all4.onrender.com)
- **Database**: MongoDB Atlas
- **Storage**: AWS S3 for avatar uploads
- **Email**: Gmail SMTP for OTP verification

All sensitive credentials are stored as environment variables and are **NOT** in the codebase.

---

## Pre-Deployment Checklist

- [ ] All environment variables are set in Render and Vercel dashboards
- [ ] MongoDB Atlas connection string is active
- [ ] AWS S3 credentials are valid and not expired
- [ ] Gmail app password is active
- [ ] JWT_SECRET_KEY is strong and secure
- [ ] CORS whitelist includes your frontend domain
- [ ] Node version is LTS (v18 or later)
- [ ] npm packages are up to date

---

## Step-by-Step Deployment

### Step 1: Backend Deployment (Render)

1. **Navigate to Render Dashboard:**
   - Go to: https://dashboard.render.com/
   - Select service: `hangout-all4`

2. **Verify Environment Variables:**
   - Click: Settings → Environment Variables
   - Ensure all these are set:
     ```
     PORT=8000
     NODE_ENV=production
     CLIENT_URL=https://hangout-one-chi.vercel.app
     MONGO_URI=<your_mongodb_atlas_connection_string>
     JWT_SECRET_KEY=<your_secure_random_string>
     EMAIL_USER=<your_gmail_address>
     EMAIL_PASS=<your_gmail_app_password>
     AWS_ACCESS_KEY_ID=<your_aws_key>
     AWS_SECRET_ACCESS_KEY=<your_aws_secret>
     AWS_REGION=us-east-1
     AWS_S3_BUCKET=hangoutavatar
     ```

3. **Trigger Deployment:**
   - Backend auto-deploys on git push to main
   - Or: Click "Recompile" in Render dashboard
   - Watch deployment logs for any errors

4. **Verify Backend is Running:**
   - Visit: https://hangout-all4.onrender.com/
   - Should show Express server response or 404 (expected)
   - Check Render logs for errors

### Step 2: Frontend Deployment (Vercel)

1. **Navigate to Vercel Dashboard:**
   - Go to: https://vercel.com/dashboard
   - Select project: `hangout-one-chi`

2. **Verify Environment Variables:**
   - Go to: Settings → Environment Variables
   - Add/Update for **Production** environment:
     ```
     VITE_BACKEND_URL=https://hangout-all4.onrender.com
     ```

3. **Trigger Deployment:**
   - Frontend auto-deploys on git push to main
   - Or: Click "Redeploy" in Vercel dashboard
   - Watch deployment logs

4. **Verify Frontend is Running:**
   - Visit: https://hangout-one-chi.vercel.app
   - Page should load without errors
   - Check browser console for CORS issues

---

## Pushing Code Changes

```bash
# From project root
cd /Users/anandhu/Desktop/Hangout

# Add all changes
git add .

# Create meaningful commit
git commit -m "Production deployment ready"

# Push to main (triggers auto-deploy on both platforms)
git push origin main
```

✅ This triggers automatic deployment on both Render and Vercel.

---

## Post-Deployment Testing

### 1. Frontend Accessibility
- [ ] Open https://hangout-one-chi.vercel.app
- [ ] Page loads within 3 seconds
- [ ] No console errors (F12 → Console)
- [ ] Layout renders correctly on desktop and mobile

### 2. Authentication Flow
- [ ] Sign up with new email account
  - Check email for verification OTP
  - Verify OTP to complete signup
- [ ] Sign in with credentials
- [ ] Verify JWT token is set in cookies (F12 → Application → Cookies)
- [ ] Logout clears session

### 3. Real-Time Features
- [ ] Open F12 Console
- [ ] Should see: `[Socket] connected` message
- [ ] No `ERR_CONNECTION_REFUSED` errors
- [ ] Check Network → WebSocket tab shows `/socket.io` connections

### 4. Core Features Testing
- [ ] **Posts**: Create, view, delete posts
- [ ] **Comments**: Add comments to posts
- [ ] **Follow**: Follow/unfollow users
- [ ] **Notifications**: Receive real-time notifications
- [ ] **Avatar Upload**: Upload profile picture
  - Verify image appears on profile
  - Check upload doesn't exceed 2MB limit
- [ ] **Search**: Search for posts/users
- [ ] **Messaging**: Send/receive messages

### 5. API Testing (Browser Developer Tools)
- Open F12 → Network tab
- Make API calls (login, create post, etc.)
- Verify all requests go to: `https://hangout-all4.onrender.com`
- Check response status codes are 2xx or 3xx (not 5xx)
- No 404 errors for API endpoints

### 6. Security Verification
- [ ] No hardcoded URLs in Network tab
- [ ] No credentials in localStorage/sessionStorage
- [ ] HTTPS is enforced (lock icon in address bar)
- [ ] CSP headers are set (F12 → Console, no CSP violations)
- [ ] No sensitive data in Network responses

### 7. Performance Checks
- [ ] Page load time < 5 seconds
- [ ] Images load quickly (check Network tab)
- [ ] No memory leaks (DevTools → Memory tab)
- [ ] Smooth scrolling and interactions

---

## Common Issues & Solutions

### Issue: API calls returning 404
**Symptoms:** Network tab shows requests to `https://hangout-one-chi.vercel.app/api/*`  
**Solution:**
```
1. Check Vercel environment variable: VITE_BACKEND_URL
2. Should be: https://hangout-all4.onrender.com
3. Redeploy frontend after changing
```

### Issue: Socket won't connect
**Symptoms:** F12 Console shows `ERR_CONNECTION_REFUSED`  
**Solution:**
```
1. Verify backend is running at https://hangout-all4.onrender.com
2. Check backend logs for errors
3. Verify CORS includes frontend domain
4. Check Network tab for WebSocket connection attempts
```

### Issue: CORS error in Console
**Error:** `Access to XMLHttpRequest blocked by CORS policy`  
**Solution:**
```
1. Backend CORS whitelist needs frontend domain
2. Edit backend/server.js CORS config
3. Add your frontend URL to allowedOrigins
4. Redeploy backend
5. Wait 2-3 minutes for Render to start new instance
```

### Issue: Images not loading
**Solution:**
```
1. Check AWS S3 bucket is public (or authenticated)
2. Verify AWS credentials are correct
3. Check S3 bucket name matches in code
4. Verify file upload to S3 succeeded (check CloudWatch logs)
```

### Issue: Email verification not working
**Solution:**
```
1. Check Gmail app password is set (not regular password)
2. Enable "Less secure app access" or "App passwords" in Gmail
3. Verify EMAIL_USER and EMAIL_PASS in Render environment
4. Check email isn't in spam folder
5. Verify email template/service works (test locally first)
```

### Issue: Database connection failing
**Solution:**
```
1. Verify MongoDB Atlas connection string is correct
2. Check IP whitelist in MongoDB Atlas (may need to add Render IP)
3. Verify database user password is correct
4. Check MONGO_URI format in environment variables
```

---

## Monitoring & Maintenance

### Daily Checks
- Monitor Render logs for backend errors
- Monitor Vercel logs for frontend errors
- Check uptime dashboards

### Weekly Checks
- Review error logs
- Test core features on different devices
- Check performance metrics

### Monthly Checks
- Review and rotate secrets if needed
- Update dependencies
- Analyze user feedback
- Plan improvements

### Useful Links
- Render Dashboard: https://dashboard.render.com/
- Vercel Dashboard: https://vercel.com/dashboard
- MongoDB Atlas: https://cloud.mongodb.com
- AWS S3: https://s3.console.aws.amazon.com
- GitHub Repo: https://github.com/devwithanandhukannan/Hangout

---

## Rollback Procedure

If something goes wrong in production:

### Backend Rollback (Render)
```
1. Go to: https://dashboard.render.com/
2. Select: hangout-all4 service
3. Go to: Deployments tab
4. Find previous successful deployment
5. Click: "Redeploy"
```

### Frontend Rollback (Vercel)
```
1. Go to: https://vercel.com/dashboard
2. Select: hangout-one-chi project
3. Go to: Deployments tab
4. Find previous successful deployment
5. Click: "Redeploy"
```

---

## Security Reminders

⚠️ **CRITICAL:**
- Never commit `.env` files with real credentials
- Never hardcode API URLs in code
- Use environment variables for all sensitive data
- Rotate credentials periodically
- Monitor access logs for suspicious activity
- Use strong JWT secret (minimum 32 characters)

✅ **Best Practices:**
- Keep dependencies updated
- Enable GitHub secret scanning
- Use environment variable tools in IDE
- Review logs regularly
- Test locally before deploying to production
- Document any configuration changes

---

## Performance Optimization Tips

1. **Frontend**
   - Enable production build (Vite automatically does this)
   - Use lazy loading for routes
   - Optimize images before upload
   - Cache bust static assets

2. **Backend**
   - Enable database connection pooling
   - Use caching headers for responses
   - Compress responses (gzip)
   - Monitor and optimize slow queries

3. **Database**
   - Create indexes on frequently queried fields
   - Regularly backup data
   - Monitor storage usage
   - Clean up old logs

---

## Support & Resources

**Project Documentation:**
- [Project Description](documentation/01-project-description.md)
- [Features & Scope](documentation/02-scope-and-features.md)
- [Workflow Diagrams](documentation/04-workflow-diagrams.md)
- [Future Enhancements](documentation/05-future-enhancements.md)

**External Documentation:**
- [Express.js Documentation](https://expressjs.com/)
- [React Documentation](https://react.dev)
- [MongoDB Documentation](https://docs.mongodb.com)
- [Socket.io Documentation](https://socket.io/docs/)
- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/)

---

**Version:** 1.0.0  
**Status:** ✅ Production Ready  
**Last Updated:** May 19, 2026
