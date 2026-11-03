# horkos-oss — dependency-free; a slim Python base is all it needs.
FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Runs directory is a volume so scan output persists across restarts.
VOLUME ["/data/runs"]
EXPOSE 8787

# Serve the dashboard, bound to all interfaces INSIDE the container; publish it
# to localhost on the host (docker run -p 127.0.0.1:8787:8787 ...) and front it
# with your own proxy + auth if you expose it further.
CMD ["horkos-web", "/data/runs", "0.0.0.0", "8787"]
