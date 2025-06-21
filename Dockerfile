FROM python:3.12-alpine

ENV CONFIG_PATH="/app/config.ini" \
    POETRY_HOME="/opt/poetry" \
    PATH="/opt/poetry/bin:$PATH"

RUN apk add --no-cache curl
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy only requirements to cache them in docker layer
WORKDIR /app
COPY poetry.lock pyproject.toml README.md /app/

# Project initialization
RUN cd /app && poetry update && poetry install --no-interaction --no-ansi

# Creating folders, and files project
COPY . /app
RUN chmod 744 /app/main.py
RUN crontab /app/cronjob

# Start cron in foreground
ENTRYPOINT ["crond", "-f"]