FROM python:3.12-slim

WORKDIR /app
COPY relay.py .

# Hosts a clearance was obtained for, kept across restarts (mounted as a volume in compose).
RUN mkdir /data && chown nobody /data
VOLUME /data

ENV PORT=8080
EXPOSE 8080
USER nobody

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8080') + '/health', timeout=4)"

CMD ["python", "-u", "relay.py"]
