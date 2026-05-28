FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Run the Vite dev server
CMD ["npm", "run", "dev", "--", "--host"]
