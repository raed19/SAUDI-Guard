
# ===== CELL 4: Utils (paste utils.py code) =====
# utils.py - Utility Functions

"""
Utility functions for Arabic text processing
"""
import re
import pandas as pd

import re
import pandas as pd


def contains_arabic(text):
    """Check if text contains Arabic characters"""

    if text is None:
        return False

    if isinstance(text, float) and pd.isna(text):
        return False

    text = str(text).strip()

    if not text:
        return False

    arabic_pattern = re.compile(
        r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]'
    )

    return bool(arabic_pattern.search(text))


def preprocess_arabic_text(text):
    """Clean and normalize Arabic text"""

    if text is None:
        return ""

    if isinstance(text, float) and pd.isna(text):
        return ""

    text = str(text)

    # Remove Arabic diacritics
    text = re.sub(r'[\u064B-\u065F\u0670]', '', text)

    # Normalize letters
    text = re.sub(r'[إأآا]', 'ا', text)
    text = re.sub(r'ى', 'ي', text)
    text = re.sub(r'ة', 'ه', text)

    # Remove extra spaces
    text = ' '.join(text.split())

    return text.strip()


# High-precision fraud terms — rarely appear in benign reviews
STRONG_FRAUD_KEYWORDS = {
    'نصب': 'fraud/scam',
    'نصابين': 'scammers',
    'احتيال': 'deception',
    'سرقه': 'theft',
    'سرقوا': 'they stole',
    'اختراق': 'hacking',
    'تجسس': 'spying',
    'هكر': 'hacker',
    'فيروس': 'virus',
    'وهمي': 'fake',
}

# Ambiguous terms — common in ordinary complaints, weak evidence alone
WEAK_FRAUD_KEYWORDS = {
    'خداع': 'cheating',
    'كذب': 'lying',
    'حرام': 'forbidden/wrong',
    'سرق': 'stealing',
    'فلوس': 'money',
    'ضياع': 'loss',
}


def detect_arabic_fraud_keywords(text):
    """Detect fraud keywords, split by evidential strength.
    Returns dict: {'strong': [...], 'weak': [...], 'all': [...]}"""
    result = {'strong': [], 'weak': [], 'all': []}
    if not text:
        return result

    text = preprocess_arabic_text(text)

    for kw, tr in STRONG_FRAUD_KEYWORDS.items():
        if kw in text:
            result['strong'].append(f"{kw} ({tr})")
    for kw, tr in WEAK_FRAUD_KEYWORDS.items():
        if kw in text:
            result['weak'].append(f"{kw} ({tr})")

    result['all'] = result['strong'] + result['weak']
    return result



def analyze_arabic_text_statistics(app_data):
    """Generate Arabic review statistics from JSON app data"""
    stats = {
        'total_reviews': 0,
        'arabic_reviews': 0,
        'fraud_keywords_found': [],        # kept for backward compat = all
        'strong_fraud_keywords': [],
        'weak_fraud_keywords': [],
        'strong_keyword_review_count': 0,  # how many DISTINCT reviews had a strong kw
        'avg_review_length': 0,
        'has_arabic_description': False,
    }

    reviews = []
    reviews_data = app_data.get("reviews_ar", [])

    if isinstance(reviews_data, list):
        for review_obj in reviews_data:
            if not isinstance(review_obj, dict):
                continue
            review_text = review_obj.get("text_norm") or review_obj.get("text", "")
            if not review_text:
                continue
            review_text = str(review_text).strip()
            stats['total_reviews'] += 1

            if contains_arabic(review_text):
                stats['arabic_reviews'] += 1
                reviews.append(review_text)

                kws = detect_arabic_fraud_keywords(review_text)
                stats['strong_fraud_keywords'].extend(kws['strong'])
                stats['weak_fraud_keywords'].extend(kws['weak'])
                if kws['strong']:
                    stats['strong_keyword_review_count'] += 1

    if reviews:
        stats['avg_review_length'] = sum(len(r) for r in reviews) / len(reviews)

    description = app_data.get('description_norm') or app_data.get('description_ar') or ''
    stats['has_arabic_description'] = contains_arabic(description)

    stats['strong_fraud_keywords'] = list(set(stats['strong_fraud_keywords']))
    stats['weak_fraud_keywords'] = list(set(stats['weak_fraud_keywords']))
    stats['fraud_keywords_found'] = stats['strong_fraud_keywords'] + stats['weak_fraud_keywords']

    stats['rating_count'] = float(app_data.get('rating_count', 0) or 0)

    return stats

