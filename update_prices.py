#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_prices.py — 주식 농장 시세 자동 갱신 (깃허브 Actions에서 실행)

하는 일
  1. farm-data.js를 비밀번호(깃허브 Secret FARM_PASSWORD)로 열어 보유 종목의 코드·수량·원금을 읽어요.
  2. 종목마다 마지막 주가를 받아요. 국내는 네이버 증권, 미국은 야후 파이낸스, 환율도 야후(안 되면 open.er-api.com).
  3. 평가액을 계산해 같은 비밀번호로 잠근 prices.js를 만들어요. 화면(index.html)이 이걸 읽어 평가액·수익률·비중을 바꿔요.

지키는 것
  - 저장소가 공개라서 실행 기록(로그)도 누구나 볼 수 있어요. 그래서 종목 이름, 코드, 금액은 절대 출력하지 않고 개수만 출력해요.
  - 받은 가격이 캡처 때 가격의 0.4배~2.5배를 벗어나면 잘못 받은 값으로 보고 버려요. 그 종목은 캡처 숫자 그대로 보여요.
  - 하나도 못 받으면 prices.js를 만들지 않고 끝나요(화면은 캡처 숫자로 보여요).
"""
import argparse, base64, datetime, json, os, re, sys, time, unicodedata
import urllib.parse, urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
KST = datetime.timezone(datetime.timedelta(hours=9))
b64d = lambda s: base64.b64decode(s)
b64e = lambda b: base64.b64encode(b).decode('ascii')


def get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'application/json,text/plain,*/*'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def num(v):
    try:
        x = float(str(v).replace(',', '').strip())
        return x if x > 0 else None
    except (TypeError, ValueError):
        return None


def yahoo(symbol):
    q = urllib.parse.quote(symbol)
    for host in ('query1', 'query2'):
        try:
            j = get_json('https://%s.finance.yahoo.com/v8/finance/chart/%s?range=5d&interval=1d' % (host, q))
            p = num(j['chart']['result'][0]['meta'].get('regularMarketPrice'))
            if p:
                return p
        except Exception:
            pass
        time.sleep(0.4)
    return None


def naver_kr(code):
    try:
        j = get_json('https://m.stock.naver.com/api/stock/%s/basic' % urllib.parse.quote(code))
        return num(j.get('closePrice'))
    except Exception:
        return None


def usd_krw():
    p = yahoo('KRW=X')
    if p and 900 < p < 2500:
        return p
    try:
        p = num(get_json('https://open.er-api.com/v6/latest/USD')['rates']['KRW'])
        if p and 900 < p < 2500:
            return p
    except Exception:
        pass
    return None


def read_box(path):
    t = open(path, encoding='utf-8').read()
    m = re.search(r'=\s*(\{.*\})\s*;?\s*$', t, re.S)
    return json.loads(m.group(1))


def derive(password, box):
    pw = unicodedata.normalize('NFC', password).encode('utf-8')
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b64d(box['salt']), iterations=box['iter']).derive(pw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default='farm-data.js')
    ap.add_argument('--out', default='prices.js')
    a = ap.parse_args()

    password = os.environ.get('FARM_PASSWORD', '')
    if not password:
        print('FARM_PASSWORD 비밀값이 없어요. 저장소 Settings > Secrets and variables > Actions에서 넣어 주세요.')
        return 1
    box = read_box(a.data)
    key = derive(password, box)
    try:
        app = json.loads(AESGCM(key).decrypt(b64d(box['iv']), b64d(box['ct']), None).decode('utf-8'))
    except Exception:
        print('farm-data.js가 열리지 않아요. FARM_PASSWORD가 farm-data.js를 잠근 비밀번호와 같은지 확인해 주세요.')
        return 1

    rows = [h for h in (app.get('data', {}).get('holdings') or []) if h.get('ticker') and h.get('qty')]
    fx = usd_krw() if any(h.get('cur') == 'USD' for h in rows) else None
    items, cache, skipped = {}, {}, 0
    for h in rows:
        t, cur = str(h['ticker']), h.get('cur')
        if (t, cur) not in cache:
            if cur == 'KRW':
                p = naver_kr(t) or (yahoo(t + '.KS') if t.isdigit() else None)
            else:
                p = yahoo(t)
            cache[(t, cur)] = p
            time.sleep(0.3)
        p = cache[(t, cur)]
        if not p or (cur == 'USD' and not fx):
            skipped += 1
            continue
        pk = p * fx if cur == 'USD' else p
        old = h.get('price_krw')
        if old and not (0.4 <= pk / float(old) <= 2.5):
            skipped += 1
            continue
        items[h['id']] = {'value': int(round(pk * float(h['qty']))), 'price_krw': int(round(pk))}

    print('시세 %d/%d개 받음, 환율 %s' % (len(items), len(rows), '받음' if fx else '못 받음'))
    if not items:
        return 1
    now = datetime.datetime.now(KST)
    out = {'at': now.strftime('%m/%d %H:%M'), 'at_iso': now.isoformat(timespec='minutes'), 'fx': round(fx, 2) if fx else None,
           'items': items, 'n': len(items), 'of': len(rows)}
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), None)
    res = {'v': 1, 'kdf': box.get('kdf', 'PBKDF2-SHA256'), 'iter': box['iter'], 'salt': box['salt'], 'iv': b64e(iv), 'ct': b64e(ct)}
    with open(a.out, 'w', encoding='ascii') as f:
        f.write('window.FARM_PRICES=' + json.dumps(res, separators=(',', ':')) + ';\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
