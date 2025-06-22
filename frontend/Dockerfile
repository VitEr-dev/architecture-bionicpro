# Build stage
FROM node:20-alpine AS build

WORKDIR /app

# Копируем только файлы, необходимые для установки зависимостей
COPY package.json package-lock.json ./

# Установка зависимостей
RUN npm install

# Копируем остальные файлы
COPY . .

# Сборка приложения
RUN npm run build

# Production stage
FROM nginx:alpine

# Копируем собранные файлы
COPY --from=build /app/build /usr/share/nginx/html

# Копируем конфиг nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]