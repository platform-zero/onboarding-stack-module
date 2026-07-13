FROM docker.io/library/python:3.12-slim

COPY stack.containers/onboarding-service/onboarding_service.py /app/onboarding_service.py

RUN groupadd --gid 10001 onboarding && \
    useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home onboarding && \
    chown -R onboarding:onboarding /app

USER onboarding

EXPOSE 8080

CMD ["python", "/app/onboarding_service.py"]
