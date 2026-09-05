FROM php:8.3-cli-bookworm AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg supervisor \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install browsers to a fixed, world-readable path (not /root/.cache, which is
# mode 700) so the jailed bot running as uid 1000 can find and launch them.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY application/package.json ./
RUN npm install --omit=dev \
    && npx playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/* /root/.npm

COPY application/ /app/
COPY run /app/run
RUN chmod +x /app/run
EXPOSE 5000
CMD ["/app/run"]

