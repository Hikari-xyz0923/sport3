FROM node:22-bookworm-slim

WORKDIR /app
COPY index.html styles.css app.js server.js leaflet.css leaflet.js ./
COPY images ./images

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV SPORT_BUDDY_DATA_DIR=/data
ENV COOKIE_SECURE=true

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "server.js"]
