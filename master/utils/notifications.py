import requests
from flask_mail import Message
from flask import current_app, render_template
from threading import Thread

# Helper function to send emails in a background thread
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail = current_app.extensions.get('mail')
            if mail:
                mail.send(msg)
                current_app.logger.info(f"Email sent successfully to {msg.recipients}")
            else:
                current_app.logger.error("Flask-Mail extension not initialized.")
        except Exception as e:
            current_app.logger.error(f"Failed to send email: {e}")

# Helper function to send webhooks in a background thread
def send_async_webhook(app, url, payload):
     with app.app_context():
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes
            current_app.logger.info(f"Webhook sent successfully to {url}, status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Failed to send webhook to {url}: {e}")
        except Exception as e:
            current_app.logger.error(f"An unexpected error occurred sending webhook to {url}: {e}")


def send_notification(subject, recipient_email=None, webhook_url=None, template=None, context=None, text_body=None):
    """Sends email and/or webhook notifications based on configuration."""
    app = current_app._get_current_object() # Get the current app instance correctly for threading

    # --- Email Notification ---
    send_email_enabled = app.config.get('MAIL_SERVER') and recipient_email
    if send_email_enabled:
        mail = app.extensions.get('mail')
        if not mail:
            app.logger.warning("Email notifications configured but Flask-Mail is not initialized.")
        else:
            sender = app.config.get('MAIL_DEFAULT_SENDER', 'simbak@localhost')
            if template and context:
                html_body = render_template(template + '.html', **context)
                if not text_body: # Attempt to generate text body if not provided
                     text_body = render_template(template + '.txt', **context) # Requires a .txt version
            elif text_body:
                html_body = None # Or generate simple HTML from text
            else:
                app.logger.error("Notification requested without template or text body.")
                return # Or send a minimal message

            msg = Message(subject, sender=sender, recipients=[recipient_email])
            msg.body = text_body
            if html_body:
                msg.html = html_body

            # Send in background thread
            thr = Thread(target=send_async_email, args=[app, msg])
            thr.start()
            app.logger.debug(f"Email sending thread started for subject: {subject}")

    # --- Webhook Notification ---
    if webhook_url:
        if not context:
            app.logger.warning("Webhook notification requested without context data.")
            payload = {"event": subject, "message": text_body or "Notification from Simbak"}
        else:
             # Structure the payload as needed for the webhook receiver
             payload = {
                 "event_type": subject.lower().replace(" ", "_"),
                 "subject": subject,
                 "details": context # Send the full context
             }
             # Add text body if available and not duplicating context massively
             if text_body and "message" not in payload["details"]:
                 payload["details"]["message"] = text_body

        # Send in background thread
        thr_wh = Thread(target=send_async_webhook, args=[app, webhook_url, payload])
        thr_wh.start()
        app.logger.debug(f"Webhook sending thread started for URL: {webhook_url}")

    if not send_email_enabled and not webhook_url:
        app.logger.debug(f"No notification channels configured or enabled for event: {subject}")

# Example Usage within Flask routes:
# from .utils.notifications import send_notification
#
# @app.route('/some_event')
# def handle_event():
#     # ... do something ...
#     client = Client.query.get(1) # Example client
#     settings = Setting.query.first() # Get global settings
#
#     subject = "Backup Job Completed"
#     context = {
#         'client_name': client.name,
#         'job_name': 'Daily Web Files',
#         'status': 'Success',
#         'timestamp': datetime.utcnow()
#     }
#     text_body = f"Backup job 'Daily Web Files' for client '{client.name}' completed successfully."
#
#     send_notification(
#         subject=subject,
#         recipient_email=settings.notification_email, # Get from settings DB
#         webhook_url=settings.notification_webhook_url, # Get from settings DB
#         template='notifications/backup_complete', # Assumes templates/notifications/backup_complete.html/txt exist
#         context=context,
#         text_body=text_body
#     )
#     return "Event processed"
