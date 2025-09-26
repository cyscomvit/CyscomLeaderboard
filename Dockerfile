FROM python:3.12-slim AS requirements-image

ENV PYTHONUNBUFFERED=1

RUN ["pip","install","poetry>=2.0.0,<3.0.0"]

RUN ["poetry","self","add","poetry-plugin-export"]

WORKDIR /export

COPY pyproject.toml poetry.lock ./

RUN ["poetry","export","--format","requirements.txt","--output","requirements.txt"]

FROM python:3.12-slim AS runtime-image

LABEL description="CYSCOM VIT's leaderboard"

ENV PYTHONUNBUFFERED=1

COPY --from=requirements-image /export/requirements.txt requirements.txt

RUN ["pip","install","gunicorn"]

RUN ["useradd","--create-home","cyscom-docker"]

USER cyscom-docker

RUN ["pip","install","--requirement","requirements.txt"]

WORKDIR /home/cyscom-docker/opensrc-website

COPY . .

CMD gunicorn --bind 0.0.0.0:5000 --workers 2 wsgi:app