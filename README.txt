Zero Security Framework
إطار عمل أمن الويب المتقدم
================================

المبرمج: SayerLinux
البريد الإلكتروني: SayerLinux1@gmail.com
GitHub: https://github.com/SaudiLinux/Zero.git

نبذة عن الأداة:
===============
Zero هو إطار عمل شامل لاختبار أمن تطبيقات الويب، مصمم لاكتشاف الثغرات الأمنية في المواقع الإلكترونية.

المميزات:
========
• كشف حقن SQL
• فحص XSS (البرمجة عبر المواقع)
• اختبار CSRF
• اكتشاف الملفات المخفية
• تجاوز جدران الحماية
• استخراج بيانات قاعدة البيانات
• تقارير JSON مفصلة

المتطلبات:
=========
• Python 3.6 أو أحدث
• pip (مدير حزم Python)
• اتصال إنترنت نشط

طريقة التثبيت:
=============

1. تحميل الأداة:
   git clone https://github.com/SaudiLinux/Zero.git
   cd Zero

2. تثبيت المتطلبات:
   pip install -r requirements.txt

طريقة الاستخدام:
===============

الاستخدام الأساسي:
python Zero.py <عنوان_الموقع>

أمثلة على الاستخدام:
===================

1. فحص موقع إلكتروني:
   python Zero.py https://example.com

2. فحص عنوان IP:
   python Zero.py 192.168.1.100

3. فحص موقع محلي:
   python Zero.py http://localhost:8080

4. فحص موقع معين:
   python Zero.py https://tayseerme.com/tayseer-admin/

ملاحظات مهمة:
=============

• استخدم الأداة فقط على المواقع التي تمتلكها أو لديك إذن صريح بفحصها
• الأداة مصممة للأغراض التعليمية والاختبار المصرح به فقط
• تأكد من الالتزام بالقوانين المحلية والدولية
• سيتم إنشاء تقرير JSON بعد كل فحص يحتوي على جميع النتائج

البحث عن عناوين URL المحددة:
============================

يمكن للأداة البحث عن مسارات إدارية محددة مثل:
• inurl:admin - البحث عن عناوين URL التي تحتوي على "admin"
• في الملف common.txt تم إضافة مسارات إدارية متعددة
• أمثلة: admin/, admin/dashboard, admin/login, site/admin, panel/admin

🛡️ كشف ثغرات Log4Shell الشاملة:
الآن يدعم Zero Security Framework كشف ثغرات Log4Shell (CVE-2021-44228) بشكل شامل عبر:
- الكشف عن بعد عبر حقول HTTP المختلفة (User-Agent, X-Forwarded-For, Referer)
- تحليل المحتوى الثابت للكشف عن إصدارات Log4j الضعيفة
- فحص ملفات الإعدادات المحلية (log4j2.xml, log4j.properties)
- فحص ملفات JAR الخاصة بـ Log4j
- الكشف عن أنماط حقن JNDI
- فحص الاستجابات المرتجعة لوجود حمولات Log4Shell

### اكتشاف قواعد البيانات والجداول والأعمدة المحددة
الإطار الآن يدعم البحث المتقدم عن:
- قواعد البيانات المحددة (MySQL, PostgreSQL, SQLite, MongoDB)
- الجداول المحددة (users, admin, customers, accounts)
- الأعمدة الحساسة (username, password, email, credit_card, ssn)
- ملفات التكوين وملفات النسخ الاحتياطي
- مخططات قواعد البيانات وهياكلها

أنماط البحث الجديدة تشمل:
- `filetype:sql "CREATE TABLE users" OR "CREATE TABLE admin"`
- `filetype:sql "INSERT INTO" ("username" OR "password" OR "email")`
- `filetype:sql "SELECT * FROM" ("users" OR "admin" OR "customers")`
- `filetype:conf "database.conf" OR "mysql.conf" OR "postgres.conf"`
- `filetype:env ".env" "DATABASE_URL" OR "DB_HOST" OR "DB_NAME"`
- `intitle:"index of" "backup/" "*.sql" OR "*.bak" OR "*.dump"`
- `filetype:sql "information_schema" OR "mysql.user" OR "pg_tables"`

البحث عن نصوص محددة داخل الصفحات (intext):
========================================

• يمكن للأداة البحث عن كلمات أو نصوص محددة داخل محتوى الصفحات
• يتم فحص الكلمات الحساسة مثل: username، password، secret، key، token، database
• النتائج تظهر في التقرير مع السياق المحيط بالكلمة الموجودة
• مثال: البحث عن كلمة "password" في جميع الصفحات الممسوحة

### اكتشاف ثغرات CVE المحددة
الإطار الآن يدعم البحث المتقدم عن الثغرات الأمنية المعروفة من خلال:
- البحث عن CVEs المحددة (CVE-2021-44228, CVE-2021-34527, CVE-2020-1472, إلخ)
- اكتشاف قواعد بيانات CVE الرسمية
- البحث في قواعد بيانات الاستغلال (Exploit DB)
- اكتشاف التنبيهات الأمنية والبلاغات
- تحديد الإصدارات البرمجية الضعيفة

أنماط البحث الجديدة تشمل:
- `intext:"CVE-2021-44228" OR "Log4Shell" OR "Log4j vulnerability"`
- `intext:"CVE-2020-1472" OR "Zerologon" OR "Netlogon vulnerability"`
- `intext:"CVE-2021-26855" OR "ProxyLogon" OR "Exchange vulnerability"`
- `inurl:"cve.mitre.org" OR "nvd.nist.gov" OR "cvedetails.com"`
- `inurl:"exploit-db.com" OR "exploitdb.com" OR "packetstormsecurity.com"`
- `filetype:pdf "CVE-" OR "vulnerability report" OR "security advisory"`
- `intext:"vulnerable version" OR "affected version" OR "fixed in version"`

### البحث عن نصوص محددة داخل الصفحات (intext)
الإطار الآن يدعم البحث المتقدم عن نصوص محددة داخل محتوى الصفحات باستخدام أنماط intext:

**أنواع النصوص التي يمكن البحث عنها:**
- **كلمات المرور وأسماء المستخدمين:** البحث عن كلمة "password" مع "username" أو "admin"
- **المعلومات الحساسة:** أرقام بطاقات الائتمان، معلومات شخصية، بيانات بنكية
- **الثغرات الأمنية:** نصوص تشير إلى وجود ثغرات مثل "sql injection" أو "xss"
- **إعدادات الخوادم:** عناوين IP، منافذ، إعدادات قواعد البيانات
- **ملفات التهيئة:** مفاتيح API، توكنات JWT، أسرار OAuth
- **ملاحظات المطورين:** TODO، FIXME، ملاحظات تصحيح الأخطاء

**أنماط البحث intext المتقدمة:**
- `intext:"password" intext:"username" filetype:txt` - البحث عن كلمات مرور في ملفات نصية
- `intext:"credit card" intext:"cvv" filetype:xlsx` - البحث عن معلومات بطاقات ائتمان
- `intext:"sql injection" intext:"vulnerable" site:*.edu.sa` - البحث عن ثغرات SQL في مواقع تعليمية
- `intext:"server ip" intext:"port" filetype:txt` - البحث عن إعدادات الخوادم
- `intext:"api_key" intext:"secret_key" filetype:yaml` - البحث عن مفاتيح API
- `intext:"TODO" intext:"FIXME" site:*.com.sa` - البحث عن ملاحظات المطورين

**أمثلة عملية على استخدام intext:**
```
# البحث عن كلمات مرور في ملفات تكوين
intext:"DB_PASSWORD" intext:"DB_USERNAME" filetype:env

# البحث عن مفاتيح API
intext:"api_key" intext:"sk-" filetype:env

# البحث عن بيانات حساسة
intext:"national id" intext:"iqama" filetype:xlsx

# البحث عن ثغرات أمنية
intext:"directory traversal" intext:"../../../" filetype:log

# البحث عن إعدادات الخوادم المحلية
intext:"localhost" intext:"127.0.0.1" filetype:config
```

**مزايا البحث باستخدام intext:**
- ✅ البحث الدقيق عن نصوص محددة داخل المحتوى
- ✅ دعم أنواع ملفات متعددة (txt, pdf, xlsx, json, yaml)
- ✅ إمكانية دمج مع عوامل تصفية أخرى (filetype, site, inurl)
- ✅ نتائج مركزة على المحتوى المطلوب فقط
- ✅ مناسب لاكتشاف المعلومات الحساسة والثغرات

**نصائح للاستخدام الفعال:**
1. استخدم علامات الاقتباس للبحث عن عبارات كاملة
2. جمع بين عدة كلمات intext للحصول على نتائج أكثر دقة
3. استخدم filetype لتحديد نوع الملف المطلوب
4. استخدم site لتقييد البحث لمواقع محددة
5. جرب كلمات مفتاحية متعددة للحصول على أفضل النتائج

البحث المتقدم باستخدام أنماط Google Dorking:
=======================================

• خوادم FTP المفتوحة: index of /ftp، index of /pub، public ftp
• ملفات تكوين WordPress: wp-config.php، wp-config.txt، wp-config.bak
• مفاتيح SSH الخاصة: BEGIN OPENSSH PRIVATE KEY، id_rsa، authorized_keys
• لوحات التحكم والبوابات: SSL Network Extender Login، Admin Login، Control Panel
• ملفات التكوين: proftpd.conf، apache2.conf، nginx.conf، my.cnf
• قواعد البيانات والسجلات: *.sql، *.db، test_database، root database

الملفات المهمة:
=============

• Zero.py - الملف الرئيسي للأداة
• common.txt - قائمة الملفات الشائعة للبحث
• requirements.txt - قائمة المتطلبات
• zero_logo.svg - شعار الأداة
• AUTHORS - معلومات المبرمج

الإخراج:
=======
بعد كل فحص، سيتم إنشاء ملف تقرير بصيغة JSON يحتوي على:
- الثغرات المكتشفة
- الملفات المخفية
- بيانات قاعدة البيانات
- حالة تجاوز جدار الحماية
- تاريخ ووقت الفحص

للمساعدة والدعم:
===============

البريد الإلكتروني: SayerLinux1@gmail.com
GitHub: https://github.com/SaudiLinux/Zero.git

تنبيه أمني:
==========
هذه الأداة مخصصة للاختبار الأمني المصرح به فقط. يجب الحصول على إذن كتابي قبل استخدامها على أي نظام.