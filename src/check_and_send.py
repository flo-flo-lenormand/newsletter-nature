"""
Newsletter Nature — Script d'envoi automatique

Ce script surveille une boite Gmail dediee. Quand le pere envoie un email
a cette adresse, le script extrait le contenu et le redistribue a tous
les abonnes via l'API Brevo.

Usage:
    python src/check_and_send.py

Variables d'environnement requises:
    GMAIL_USER          - Adresse Gmail dediee (ex: newsletter-nature@gmail.com)
    GMAIL_APP_PASSWORD  - Mot de passe d'application Gmail
    BREVO_API_KEY       - Cle API Brevo
    SENDER_EMAIL        - Adresse email du pere (filtre les mails entrants)
    BREVO_LIST_ID       - ID de la liste de contacts Brevo
    SENDER_NAME         - Nom de l'expediteur affiche dans les newsletters
    GITHUB_TOKEN        - Token GitHub pour heberger les images (fourni automatiquement par Actions)
    GITHUB_REPOSITORY   - Nom du repo (fourni automatiquement par Actions)
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import base64
import hashlib
import json
import logging
import os
import re
import time
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

GMAIL_USER = os.environ["GMAIL_USER"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
BREVO_API_KEY = os.environ["BREVO_API_KEY"]
SENDER_EMAIL = os.environ["SENDER_EMAIL"]
BREVO_LIST_ID = int(os.environ.get("BREVO_LIST_ID", "1"))
SENDER_NAME = os.environ.get("SENDER_NAME", "Newsletter Nature")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")


EMAIL_TEMPLATE = """\
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{subject}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f0e8; font-family: Georgia, 'Times New Roman', serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f0e8;">
<tr><td align="center" style="padding: 20px 10px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 8px; overflow: hidden;">
<!-- Header -->
<tr><td style="background-color: #2c5f2d; padding: 24px 32px; text-align: center;">
<h1 style="margin: 0; color: #ffffff; font-size: 24px; font-family: Georgia, serif;">Instant Nature</h1>
</td></tr>
<!-- Content -->
<tr><td style="padding: 32px; font-size: 16px; line-height: 1.7; color: #2c3e2d; font-family: Georgia, 'Times New Roman', serif;">
{content}
</td></tr>
<!-- Footer -->
<tr><td style="padding: 16px 32px; text-align: center; font-size: 12px; color: #a0b0a0; border-top: 1px solid #e8e8e8;">
<p style="margin: 0;">Vous recevez cet email car vous etes abonne(e) a Instant Nature.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def connect_gmail():
    """Se connecte a Gmail via IMAP et retourne la connexion."""
    log.info("Connexion a Gmail via IMAP...")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)
    mail.select("inbox")
    return mail


def decode_mime_header(header_value):
    """Decode un header MIME (sujet, expediteur, etc.)."""
    if header_value is None:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result)


def find_unread_from_sender(mail):
    """Cherche les emails non lus provenant de l'adresse du pere."""
    search_criteria = f'(UNSEEN FROM "{SENDER_EMAIL}")'
    log.info("Recherche d'emails non lus de %s...", SENDER_EMAIL)
    status, data = mail.search(None, search_criteria)
    if status != "OK":
        log.warning("Recherche IMAP echouee: %s", status)
        return []

    msg_ids = data[0].split()
    log.info("Trouve %d email(s) non lu(s).", len(msg_ids))
    return msg_ids


def upload_image_to_github(image_data, filename, content_type):
    """Upload une image sur le repo GitHub et retourne l'URL publique."""
    if not GITHUB_TOKEN or not GITHUB_REPOSITORY:
        log.warning("GITHUB_TOKEN ou GITHUB_REPOSITORY manquant, impossible d'heberger l'image.")
        return None

    # Creer un nom de fichier unique base sur le hash du contenu
    content_hash = hashlib.sha256(image_data).hexdigest()[:12]
    timestamp = int(time.time())
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    path = f"images/{timestamp}_{content_hash}_{safe_filename}"

    b64_content = base64.b64encode(image_data).decode("ascii")

    payload = {
        "message": f"Add newsletter image: {safe_filename}",
        "content": b64_content,
        "branch": "main",
    }

    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/contents/{path}"

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github.v3+json",
            },
            method="PUT",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPOSITORY}/main/{path}"
            log.info("Image uploadee: %s -> %s", safe_filename, raw_url)
            return raw_url
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error("Erreur upload image GitHub: %s — %s", e.code, body)
        return None


def normalize_images_in_html(html_body):
    """Ajoute des styles responsive a toutes les balises <img>."""
    def add_responsive_style(match):
        tag = match.group(0)
        # Retirer les attributs width/height existants
        tag = re.sub(r'\s+width\s*=\s*["\']?\d+["\']?', '', tag, flags=re.IGNORECASE)
        tag = re.sub(r'\s+height\s*=\s*["\']?\d+["\']?', '', tag, flags=re.IGNORECASE)
        # Ajouter le style responsive
        if 'style=' in tag:
            tag = re.sub(
                r'style\s*=\s*["\']',
                'style="max-width: 100%; height: auto; display: block; margin: 12px auto; ',
                tag,
                flags=re.IGNORECASE,
            )
        else:
            tag = tag.replace('<img', '<img style="max-width: 100%; height: auto; display: block; margin: 12px auto;"', 1)
        return tag

    return re.sub(r'<img[^>]+>', add_responsive_style, html_body, flags=re.IGNORECASE)


def extract_email_content(mail, msg_id):
    """Extrait le sujet, le corps HTML et les images d'un email."""
    status, data = mail.fetch(msg_id, "(RFC822)")
    if status != "OK":
        log.warning("Impossible de lire le message %s", msg_id)
        return None

    raw_email = data[0][1]
    msg = email.message_from_bytes(raw_email)

    subject = decode_mime_header(msg["Subject"])
    from_addr = parseaddr(msg["From"])[1]

    log.info("Email trouve — Sujet: '%s' | De: %s", subject, from_addr)

    html_body = None
    text_body = None
    inline_images = {}

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))

        if content_type == "text/html" and "attachment" not in content_disposition:
            charset = part.get_content_charset() or "utf-8"
            html_body = part.get_payload(decode=True).decode(charset, errors="replace")

        elif content_type == "text/plain" and "attachment" not in content_disposition:
            charset = part.get_content_charset() or "utf-8"
            text_body = part.get_payload(decode=True).decode(charset, errors="replace")

        elif content_type.startswith("image/"):
            content_id = part.get("Content-ID", "")
            content_id = content_id.strip("<>")
            image_data = part.get_payload(decode=True)
            if image_data:
                filename = part.get_filename() or f"image.{content_type.split('/')[1]}"
                inline_images[content_id] = {
                    "content_type": content_type,
                    "data": image_data,
                    "filename": filename,
                }

    # Si pas de HTML, convertir le texte brut en HTML simple
    if not html_body and text_body:
        paragraphs = text_body.strip().split("\n\n")
        html_parts = [f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs]
        html_body = "\n".join(html_parts)

    if not html_body:
        log.warning("Aucun contenu exploitable dans l'email.")
        return None

    # Upload les images sur GitHub et remplacer les references cid:
    for cid, img_info in inline_images.items():
        hosted_url = upload_image_to_github(
            img_info["data"], img_info["filename"], img_info["content_type"]
        )
        if hosted_url:
            cid_ref = f"cid:{cid}"
            html_body = html_body.replace(cid_ref, hosted_url)
        else:
            # Fallback: base64 data URI (ne marchera pas sur Gmail)
            b64_data = base64.b64encode(img_info["data"]).decode("ascii")
            cid_ref = f"cid:{cid}"
            data_uri = f"data:{img_info['content_type']};base64,{b64_data}"
            html_body = html_body.replace(cid_ref, data_uri)

    # Normaliser les images pour le responsive
    html_body = normalize_images_in_html(html_body)

    # Envelopper dans le template responsive
    html_body = EMAIL_TEMPLATE.format(subject=subject, content=html_body)

    return {
        "subject": subject,
        "html_body": html_body,
        "inline_images": inline_images,
    }


def send_via_brevo(subject, html_body):
    """Envoie la newsletter a toute la liste via l'API Brevo."""
    log.info("Envoi de la newsletter via Brevo...")

    contacts = get_brevo_contacts()
    if not contacts:
        log.warning("Aucun contact dans la liste Brevo. Envoi annule.")
        return False

    log.info("Envoi a %d contact(s)...", len(contacts))

    batch_size = 50
    success = True

    for i in range(0, len(contacts), batch_size):
        batch = contacts[i : i + batch_size]
        bcc_list = [{"email": c} for c in batch]

        payload = {
            "sender": {"name": SENDER_NAME, "email": GMAIL_USER},
            "to": [{"email": GMAIL_USER}],
            "bcc": bcc_list,
            "subject": subject,
            "htmlContent": html_body,
        }

        try:
            req = urllib.request.Request(
                "https://api.brevo.com/v3/smtp/email",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "api-key": BREVO_API_KEY,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                log.info(
                    "Lot %d-%d envoye (status %d).",
                    i + 1,
                    min(i + batch_size, len(contacts)),
                    resp.status,
                )
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.error("Erreur Brevo (lot %d-%d): %s — %s", i + 1, i + batch_size, e.code, body)
            success = False

    return success


def get_brevo_contacts():
    """Recupere tous les contacts de la liste Brevo."""
    contacts = []
    offset = 0
    limit = 50

    while True:
        url = (
            f"https://api.brevo.com/v3/contacts/lists/{BREVO_LIST_ID}/contacts"
            f"?limit={limit}&offset={offset}"
        )
        req = urllib.request.Request(
            url,
            headers={
                "api-key": BREVO_API_KEY,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                batch = [c["email"] for c in data.get("contacts", [])]
                contacts.extend(batch)
                if len(batch) < limit:
                    break
                offset += limit
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.error("Erreur lors de la recuperation des contacts: %s — %s", e.code, body)
            break

    log.info("Total contacts recuperes: %d", len(contacts))
    return contacts


def mark_as_read(mail, msg_id):
    """Marque un email comme lu dans Gmail."""
    mail.store(msg_id, "+FLAGS", "\\Seen")
    log.info("Email marque comme lu.")


def main():
    mail = connect_gmail()

    try:
        msg_ids = find_unread_from_sender(mail)
        if not msg_ids:
            log.info("Aucun nouvel email a traiter. Fin.")
            return

        for msg_id in msg_ids:
            content = extract_email_content(mail, msg_id)
            if content is None:
                continue

            success = send_via_brevo(content["subject"], content["html_body"])
            if success:
                mark_as_read(mail, msg_id)
                log.info("Newsletter '%s' envoyee avec succes.", content["subject"])
            else:
                log.error("Echec de l'envoi pour '%s'. Email conserve comme non lu.", content["subject"])
    finally:
        mail.logout()
        log.info("Deconnexion Gmail.")


if __name__ == "__main__":
    main()
