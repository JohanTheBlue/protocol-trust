#!/usr/bin/env python3
"""Offline EML -> SAFE REVIEW CANDIDATES (never auto-publish or auto-label).

Usage: python tools/eml_to_candidates.py /path/to/email/ --output imports/candidates.json --limit 50
No network, no attachments saved/opened, no HTML execution.
"""
import argparse
import hashlib
import html
import json
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_BODY_CHARS = 1600

class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.buf=[]
        self.ignore=0
    def handle_starttag(self, tag, attrs):
        if tag in ('script','style'): self.ignore+=1
        elif tag in ('p','div','br','li','h1','h2','h3') and not self.ignore: self.buf.append('\n')
    def handle_endtag(self, tag):
        if tag in ('script','style') and self.ignore: self.ignore-=1
        elif tag in ('p','div','li') and not self.ignore: self.buf.append('\n')
    def handle_data(self, data):
        if not self.ignore: self.buf.append(data)
    def get_text(self): return ''.join(self.buf)

def scrub(value):
    value=html.unescape(str(value or ''))
    value=re.sub(r'(?i)\b(?:hxxps?|https?|ftp)\s*:\s*//[^\s\"<>]+', '[external link]',value)
    value=re.sub(r'(?i)\b(?:www\.)[\w.-]+(?:/[^\s\"<>]*)?', '[external link]',value)
    value=re.sub(r'(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b','[email]',value)
    value=re.sub(r'(?<!\d)(?:\+?\d[\d .()\-]{7,}\d)(?!\d)','[number]',value)
    # Defanged URLs, remaining IP addresses and source domains may still be personal/sensitive.
    value=re.sub(r'(?i)\b(?:[\w.-]+\[\.\])+(?:[a-z]{2,})(?:/[^\s]*)?', '[external link]', value)
    value=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','[IP]',value)
    value=re.sub(r'[ \t]+',' ',value)
    value=re.sub(r'\n\s*\n\s*\n+', '\n\n',value)
    return value.strip()[:MAX_BODY_CHARS]

def extract(msg):
    text=[]; html_parts=[]; names=[]
    for part in msg.walk():
        if part.get_content_disposition()=='attachment':
            names.append(str(part.get_filename() or '[unnamed attachment]')[-100:])
            continue
        typ=part.get_content_type()
        if typ not in ('text/plain','text/html'): continue
        try: val=part.get_content()
        except Exception: continue
        if not isinstance(val,str): continue
        if typ=='text/plain': text.append(val)
        elif typ=='text/html':
            parser=TextOnly()
            try: parser.feed(val); html_parts.append(parser.get_text())
            except Exception: pass
    body='\n'.join(text or html_parts)
    return scrub(body),len(names)  # never include attachment data or filenames

def prepare(path, root):
    raw=path.read_bytes()
    if len(raw)>MAX_FILE_BYTES: return None
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    body,nattach=extract(msg)
    if not body: return None
    return dict(
        source_path=path.relative_to(root).as_posix(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        original_format='eml',
        subject=scrub(str(msg.get('Subject',''))),
        from_display='[redacted sender]',
        body_preview=body,
        attachment_count=nattach,
        source_status='raw_sample_candidate',
        decision=None,
        game_rule=None,
        note='Manual review needed: check context, redact remaining PII, rewrite and label. Do not directly publish this text.'
    )

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input',help='folder of .eml files, e.g. Phishing Pot email/')
    ap.add_argument('--output',default='imports/candidates.json')
    ap.add_argument('--limit',type=int,default=50)
    args=ap.parse_args()
    root=Path(args.input).resolve()
    if not root.is_dir(): ap.error('input folder not found')
    results=[]
    for f in sorted(root.rglob('*.eml')):
        try:
            cand=prepare(f,root)
            if cand: results.append(cand)
        except Exception as e:
            print(f'Skipped {f.name}: {type(e).__name__}')
        if len(results)>=args.limit: break
    dest=Path(args.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(results,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(f'{len(results)} candidates exported for MANUAL REVIEW: {dest}')

if __name__=='__main__': main()
