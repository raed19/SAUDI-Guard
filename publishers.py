
KNOWN_PUBLISHER_PREFIXES = (
    'com.google.', 'com.android.', 'com.samsung.', 'com.sec.',
    'com.huawei.', 'com.xiaomi.', 'com.miui.', 'com.oppo.', 'com.vivo.',
    'com.amazon.', 'com.alibaba.', 'com.aliexpress.', 'com.taobao.',
    'com.baidu.', 'com.tencent.', 'com.netease.', 'com.bytedance.',
    'com.zhiliaoapp.', 'com.facebook.', 'com.instagram.', 'com.whatsapp.',
    'com.twitter.', 'com.snapchat.', 'com.microsoft.', 'com.skype.',
    'com.adobe.', 'com.paypal.', 'com.ebay.', 'com.booking.',
    'com.avatrade.', 'com.etoro.', 'com.binance.', 'com.ubercab.',
    'com.careem.', 'com.talabat.', 'com.noon.', 'com.souq.',
)


def is_known_publisher(package_id):
    p = str(package_id or '').lower().strip()
    return any(p.startswith(pref) for pref in KNOWN_PUBLISHER_PREFIXES)
