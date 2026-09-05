# Portable alternative to render.yaml — for Azure Container Apps, Fly.io, Cloud Run or a VM.
#
# No dependencies to install, so there is nothing to cache and no build step. The image carries the
# committed verdict cache, which is what lets the container run with no inference key at all.
#
# Never bake a key into the image. Pass SOC_BASE_URL / SOC_MODEL / SOC_API_KEY at runtime if you
# want live reasoning; .dockerignore keeps config.json out of the build context.

FROM node:22-alpine

WORKDIR /app
# Owned by the runtime user so writeCache() can still persist verdicts if a key is supplied later.
# lib/cache.js swallows write failures by design, so root-owned files would fail silently instead.
COPY --chown=node:node . .

ENV NODE_ENV=production
# The server honours PORT first, so a platform that injects its own overrides this default.
ENV PORT=8787
EXPOSE 8787

USER node
CMD ["node", "server.js"]
