FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy application code
COPY . .

# Build for production (VITE_API_URL is baked in from .env at build time)
RUN npm run build

# ---- Serve stage ----
FROM node:20-alpine

WORKDIR /app

RUN npm install -g serve

COPY --from=builder /app/dist ./dist

# Expose port
EXPOSE 3000

# Serve the built static files
CMD ["serve", "-s", "dist", "-l", "tcp://0.0.0.0:3000"]

