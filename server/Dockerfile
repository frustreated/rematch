FROM alpine:latest
ENV PYTHONUNBUFFERED 1
RUN apk add --no-cache python3 python3-pip nginx postgresql-client

# Create rematch user and setup environment
RUN mkdir /rematch_server/
RUN addgroup rematch
RUN adduser -S -D -H -h /rematch_server rematch -G rematch
WORKDIR /rematch_server
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/ ./tests/

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/

RUN chown rematch:rematch -R /var/lib/nginx/

# Install python requirements
RUN pip install uwsgi
RUN pip install -r /rematch_server/server/requirements.txt

# Downgrade to the rematch user and set server up
# USER rematch
WORKDIR /rematch_server/server
CMD ["./docker-assets/docker-entrypoint.sh"]
