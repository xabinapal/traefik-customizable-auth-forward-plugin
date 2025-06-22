FROM docker.io/library/node:24-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY server.mjs ./

# Expose port
EXPOSE 3000

# Start server
CMD ["npm", "start"] 
