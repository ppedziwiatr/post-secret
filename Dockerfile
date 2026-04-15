FROM node:22-alpine
WORKDIR /app
COPY server.js .
ENV PORT=3000
ENV DB_PATH=/data/secrets.db
EXPOSE 3000
CMD ["node", "server.js"]
