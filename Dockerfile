FROM python:3.12-alpine

ENV CONFIG_PATH="/app/config.ini" \
    POETRY_HOME="/opt/poetry" \
    PATH="/opt/poetry/bin:$PATH"

RUN apk add --no-cache curl
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy only requirements to cache them in docker layer
WORKDIR /app
COPY poetry.lock pyproject.toml README.md /app/

# Project initialization:
RUN poetry update && poetry install --no-interaction --no-ansi

# Creating folders, and files for a project:
COPY . /app
RUN crontab /app/cronjob

# Create empty log (TAIL needs this)
RUN touch /tmp/out.log

# Start TAIL - as your always-on process (otherwise - container exits right after start)
CMD ["crond", "&&", "tail", "-f", "/tmp/out.log"]