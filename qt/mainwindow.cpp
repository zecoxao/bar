#include "mainwindow.h"
#include "worker.h"
#include "bar_bridge.h"

#include <QtWidgets>
#include <QSettings>
#include <vector>

/* keep C-string arrays alive for the duration of a blocking bridge call */
struct ArgHold {
    std::vector<QByteArray> store;
    std::vector<const char *> ptr;
    void add(const QString &s) { store.push_back(s.toUtf8()); }
    void finalize() { for (auto &b : store) ptr.push_back(b.constData()); }
};

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("bar - PS4 backup (P4BR / SCECAF) tool");

    auto *tabs = new QTabWidget;
    tabs->addTab(buildExtractTab(), tr("Extract"));
    tabs->addTab(buildCreateTab(), tr("Create"));

    m_log = new QPlainTextEdit;
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(20000);
    m_log->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    m_log->setMinimumHeight(160);

    auto *progRow = new QHBoxLayout;
    m_prog = new QProgressBar;
    progRow->addWidget(m_prog, 1);
    m_cancel = new QPushButton(tr("Cancel"));
    m_cancel->setEnabled(false);
    progRow->addWidget(m_cancel);
    connect(m_cancel, &QPushButton::clicked, this, &MainWindow::cancelJob);

    auto *central = new QWidget;
    auto *v = new QVBoxLayout(central);
    v->addWidget(tabs, 1);
    v->addWidget(new QLabel(tr("Log:")));
    v->addWidget(m_log);
    v->addLayout(progRow);
    setCentralWidget(central);
    resize(820, 680);

    QSettings s;
    xBackup->setText(s.value("x/backup").toString());
    xOut->setText(s.value("x/out").toString());
    cSource->setText(s.value("c/source").toString());
    cOut->setText(s.value("c/out").toString());
    cTmpl->setText(s.value("c/tmpl").toString());
    restoreGeometry(s.value("geom").toByteArray());
}

/* ---------------- Extract tab ---------------- */
QWidget *MainWindow::buildExtractTab() {
    auto *w = new QWidget;
    auto *form = new QFormLayout(w);

    auto folderRow = [&](QLineEdit *&edit, const QString &caption, bool pickFile) {
        auto *row = new QHBoxLayout;
        edit = new QLineEdit;
        auto *br = new QPushButton("...");
        br->setFixedWidth(32);
        row->addWidget(edit); row->addWidget(br);
        connect(br, &QPushButton::clicked, this, [this, edit, caption, pickFile] {
            QString p = pickFile
                ? QFileDialog::getOpenFileName(this, caption, edit->text(), tr("archive.dat (archive*.dat);;All files (*)"))
                : QFileDialog::getExistingDirectory(this, caption, edit->text());
            if (!p.isEmpty()) edit->setText(p);
        });
        auto *cont = new QWidget; cont->setLayout(row);
        return cont;
    };

    form->addRow(tr("Backup folder:"), folderRow(xBackup, tr("Backup folder (contains archive.dat)"), false));
    form->addRow(tr("Output folder:"), folderRow(xOut, tr("Extract to"), false));

    xVerify = new QCheckBox(tr("Verify HMAC before extract (recommended)"));
    xVerify->setChecked(true);
    xList = new QCheckBox(tr("List only (don't extract)"));
    auto *chkRow = new QHBoxLayout; chkRow->addWidget(xVerify); chkRow->addWidget(xList); chkRow->addStretch();
    auto *chkW = new QWidget; chkW->setLayout(chkRow);
    form->addRow(QString(), chkW);

    xThreads = new QSpinBox; xThreads->setRange(0, 64); xThreads->setValue(0);
    xThreads->setSpecialValueText(tr("auto"));
    form->addRow(tr("Threads:"), xThreads);

    xInc = new QLineEdit; xInc->setPlaceholderText(tr("comma-separated path prefixes, e.g. /user/,/system_data/priv/"));
    xExc = new QLineEdit; xExc->setPlaceholderText(tr("comma-separated path prefixes to skip"));
    form->addRow(tr("Include:"), xInc);
    form->addRow(tr("Exclude:"), xExc);

    xManifest = new QLineEdit; xManifest->setPlaceholderText(tr("optional: write a TSV listing to this file"));
    form->addRow(tr("Manifest:"), xManifest);

    xKey = new QLineEdit; xKey->setPlaceholderText(tr("advanced: 32 hex (blank = built-in)"));
    xHash = new QLineEdit; xHash->setPlaceholderText(tr("advanced: 64 hex (blank = built-in)"));
    form->addRow(tr("Cipher key:"), xKey);
    form->addRow(tr("HMAC key:"), xHash);

    auto *go = new QPushButton(tr("Extract"));
    connect(go, &QPushButton::clicked, this, &MainWindow::doExtract);
    form->addRow(QString(), go);
    return w;
}

/* ---------------- Create tab ---------------- */
QWidget *MainWindow::buildCreateTab() {
    auto *w = new QWidget;
    auto *form = new QFormLayout(w);

    auto folderRow = [&](QLineEdit *&edit, const QString &caption, bool pickFile) {
        auto *row = new QHBoxLayout;
        edit = new QLineEdit;
        auto *br = new QPushButton("...");
        br->setFixedWidth(32);
        row->addWidget(edit); row->addWidget(br);
        connect(br, &QPushButton::clicked, this, [this, edit, caption, pickFile] {
            QString p = pickFile
                ? QFileDialog::getOpenFileName(this, caption, edit->text(), tr("archive.dat (archive*.dat);;All files (*)"))
                : QFileDialog::getExistingDirectory(this, caption, edit->text());
            if (!p.isEmpty()) edit->setText(p);
        });
        auto *cont = new QWidget; cont->setLayout(row);
        return cont;
    };

    form->addRow(tr("Source folder:"), folderRow(cSource, tr("Source file tree (user/ and/or system_data/)"), false));
    form->addRow(tr("Output folder:"), folderRow(cOut, tr("Write backup to"), false));

    cName = new QLineEdit; form->addRow(tr("Name:"), cName);
    cLabel = new QLineEdit; form->addRow(tr("Label:"), cLabel);

    auto *tmplRow = new QHBoxLayout;
    cTmpl = new QLineEdit; cTmpl->setPlaceholderText(tr("template archive.dat (for restorable aux); blank = bundled skeleton"));
    auto *tbr = new QPushButton("...");
    tbr->setFixedWidth(32);
    auto *skelBtn = new QPushButton(tr("Make skeleton..."));
    tmplRow->addWidget(cTmpl); tmplRow->addWidget(tbr); tmplRow->addWidget(skelBtn);
    connect(tbr, &QPushButton::clicked, this, [this] {
        QString p = QFileDialog::getOpenFileName(this, tr("Template archive.dat"), cTmpl->text(), tr("archive.dat (archive*.dat);;All files (*)"));
        if (!p.isEmpty()) { cTmpl->setText(p); autofillFromTemplate(); }
    });
    connect(skelBtn, &QPushButton::clicked, this, &MainWindow::makeSkeleton);
    connect(cTmpl, &QLineEdit::editingFinished, this, &MainWindow::autofillFromTemplate);
    auto *tmplW = new QWidget; tmplW->setLayout(tmplRow);
    form->addRow(tr("Template:"), tmplW);

    cUser = new QLineEdit; form->addRow(tr("User name:"), cUser);
    cHost = new QLineEdit; form->addRow(tr("Console name:"), cHost);
    cPsid = new QLineEdit; cPsid->setPlaceholderText(tr("32 hex (OpenPSID); blank = keep template's"));
    form->addRow(tr("OpenPSID:"), cPsid);

    cSets = new QPlainTextEdit; cSets->setPlaceholderText(tr("advanced registry overrides, one per line: KEYIDHEX=STRING"));
    cSets->setMaximumHeight(70);
    form->addRow(tr("Set keys:"), cSets);

    cKeyset = new QComboBox; cKeyset->addItems({tr("auto (follow template)"), tr("new"), tr("old")});
    form->addRow(tr("Keyset:"), cKeyset);

    cVerify = new QCheckBox(tr("Self-check after create")); cVerify->setChecked(true);
    cClone  = new QCheckBox(tr("Clone mode (reproduce template byte-for-byte)"));
    auto *chkRow = new QHBoxLayout; chkRow->addWidget(cVerify); chkRow->addWidget(cClone); chkRow->addStretch();
    auto *chkW = new QWidget; chkW->setLayout(chkRow);
    form->addRow(QString(), chkW);

    auto *go = new QPushButton(tr("Create backup"));
    connect(go, &QPushButton::clicked, this, &MainWindow::doCreate);
    form->addRow(QString(), go);
    return w;
}

/* ---------------- actions ---------------- */
static QStringList splitPrefixes(const QString &s) {
    QStringList out;
    for (const QString &p : s.split(QRegularExpression("[,\\n]"), Qt::SkipEmptyParts)) {
        QString t = p.trimmed();
        if (!t.isEmpty()) out << t;
    }
    return out;
}

void MainWindow::doExtract() {
    if (m_busy) return;
    QString backup = xBackup->text().trimmed();
    if (backup.isEmpty()) { QMessageBox::warning(this, tr("Extract"), tr("Choose a backup folder.")); return; }

    auto inc = splitPrefixes(xInc->text());
    auto exc = splitPrefixes(xExc->text());
    QString out = xOut->text().trimmed();
    if (out.isEmpty()) out = backup + "_restore";
    bool verify = xVerify->isChecked(), list = xList->isChecked();
    int threads = xThreads->value();
    QString key = xKey->text().trimmed(), hash = xHash->text().trimmed(), manifest = xManifest->text().trimmed();

    startJob(tr("Extracting..."),
        [=]() -> int {
            ArgHold hi, he;
            for (const auto &s : inc) hi.add(s);
            for (const auto &s : exc) he.add(s);
            hi.finalize(); he.finalize();
            QByteArray bb = backup.toUtf8(), ob = out.toUtf8(), kb = key.toUtf8(), hb = hash.toUtf8(), mb = manifest.toUtf8();
            barx_opts o; memset(&o, 0, sizeof o);
            o.backup = bb.constData();
            o.outdir = ob.constData();
            o.keyhex = kb.constData();
            o.hashhex = hb.constData();
            o.inc = hi.ptr.data(); o.ninc = (int)hi.ptr.size();
            o.exc = he.ptr.data(); o.nexc = (int)he.ptr.size();
            o.manifest = mb.constData();
            o.do_list = list ? 1 : 0;
            o.verify = verify ? 1 : 0;
            o.nthreads = threads;
            return barx_extract(&o, &Worker::logCb, &Worker::progCb, &m_worker->cancelInt, m_worker);
        },
        [this](int rc) { log(rc == 0 ? QStringLiteral("extract: finished") : QStringLiteral("extract: rc=%1").arg(rc)); });
}

void MainWindow::doCreate() {
    if (m_busy) return;
    QString source = cSource->text().trimmed();
    QString tmpl = cTmpl->text().trimmed();
    bool clone = cClone->isChecked();
    if (!clone && source.isEmpty()) { QMessageBox::warning(this, tr("Create"), tr("Choose a source folder.")); return; }
    if (clone && tmpl.isEmpty()) { QMessageBox::warning(this, tr("Create"), tr("Clone mode needs a template.")); return; }
    QString out = cOut->text().trimmed();
    if (out.isEmpty()) { QMessageBox::warning(this, tr("Create"), tr("Choose an output folder.")); return; }

    QString name = cName->text(), label = cLabel->text(), user = cUser->text(),
            host = cHost->text(), psid = cPsid->text().trimmed();
    QStringList sets;
    for (const QString &l : cSets->toPlainText().split('\n', Qt::SkipEmptyParts))
        if (l.contains('=')) sets << l.trimmed();
    int ksIdx = cKeyset->currentIndex();   /* 0 auto, 1 new, 2 old */
    bool verify = cVerify->isChecked();

    startJob(tr("Creating backup..."),
        [=]() -> int {
            ArgHold hs;
            for (const auto &s : sets) hs.add(s);
            hs.finalize();
            QByteArray sb = source.toUtf8(), ob = out.toUtf8(), nb = name.toUtf8(), lb = label.toUtf8(),
                       tb = tmpl.toUtf8(), ub = user.toUtf8(), hb = host.toUtf8(), pb = psid.toUtf8();
            const char *ks = ksIdx == 1 ? "new" : ksIdx == 2 ? "old" : nullptr;
            barc_opts o; memset(&o, 0, sizeof o);
            o.source = sb.constData();
            o.outdir = ob.constData();
            o.name = nb.constData();
            o.label = lb.constData();
            o.tmpl = tb.constData();
            o.set_user = ub.constData();
            o.set_host = hb.constData();
            o.openpsid = pb.constData();
            o.sets = hs.ptr.data(); o.nsets = (int)hs.ptr.size();
            o.keyset = ks;
            o.verify = verify ? 1 : 0;
            o.clone = clone ? 1 : 0;
            o.make_skeleton = 0;
            return barc_create(&o, &Worker::logCb, &Worker::progCb, &m_worker->cancelInt, m_worker);
        },
        [this](int rc) { log(rc == 0 ? QStringLiteral("create: finished") : QStringLiteral("create: rc=%1").arg(rc)); });
}

void MainWindow::makeSkeleton() {
    if (m_busy) return;
    QString backup = QFileDialog::getOpenFileName(this, tr("Pick a real backup's archive.dat"),
        QString(), tr("archive.dat (archive*.dat);;All files (*)"));
    if (backup.isEmpty()) return;
    QString dir = QFileDialog::getExistingDirectory(this, tr("Save skeleton (archive.dat) into folder"));
    if (dir.isEmpty()) return;
    QString skel = dir + "/archive.dat";

    startJob(tr("Capturing skeleton..."),
        [=]() -> int {
            QByteArray sb = backup.toUtf8(), ob = skel.toUtf8();
            barc_opts o; memset(&o, 0, sizeof o);
            o.source = sb.constData();
            o.outdir = ob.constData();
            o.make_skeleton = 1;
            return barc_create(&o, &Worker::logCb, &Worker::progCb, &m_worker->cancelInt, m_worker);
        },
        [this, skel](int rc) {
            if (rc == 0) { cTmpl->setText(skel); autofillFromTemplate();
                log("skeleton: captured; template set. Now pick a Source folder and Create."); }
            else log(QStringLiteral("skeleton: rc=%1").arg(rc));
        });
}

void MainWindow::autofillFromTemplate() {
    QString tmpl = cTmpl->text().trimmed();
    if (tmpl.isEmpty()) return;
    char label[256] = {0}, psid[40] = {0}, user[160] = {0}, host[160] = {0};
    if (barc_autofill(tmpl.toUtf8().constData(), label, sizeof label, psid, sizeof psid,
                      user, sizeof user, host, sizeof host) == 0) {
        if (cLabel->text().isEmpty() && label[0]) cLabel->setText(QString::fromUtf8(label));
        if (cPsid->text().isEmpty()  && psid[0])  cPsid->setText(QString::fromUtf8(psid));
        if (cUser->text().isEmpty()  && user[0])  cUser->setText(QString::fromUtf8(user));
        if (cHost->text().isEmpty()  && host[0])  cHost->setText(QString::fromUtf8(host));
        log("identity autofilled from template");
    }
}

/* ---------------- job plumbing ---------------- */
void MainWindow::startJob(const QString &label, std::function<int()> body, std::function<void(int)> done) {
    if (m_busy) return;
    setBusy(true, label);
    m_worker = new Worker(this);
    m_worker->cancelInt = 0;
    m_worker->job = std::move(body);
    connect(m_worker, &Worker::logLine, this, [this](QString s) { log(s); }, Qt::QueuedConnection);
    connect(m_worker, &Worker::progress, this, [this](qint64 d, qint64 t) {
        if (t > 0) { m_prog->setRange(0, 1000); m_prog->setValue((int)(d * 1000 / t)); }
        else m_prog->setRange(0, 0);
    }, Qt::QueuedConnection);
    connect(m_worker, &Worker::jobFinished, this, [this, done](int rc) {
        setBusy(false, QString());
        if (done) done(rc);
        m_worker->deleteLater(); m_worker = nullptr;
    }, Qt::QueuedConnection);
    m_prog->setRange(0, 0);
    m_worker->start();
}

void MainWindow::setBusy(bool busy, const QString &label) {
    m_busy = busy;
    m_cancel->setEnabled(busy);
    if (busy && !label.isEmpty()) log("== " + label + " ==");
    if (!busy) { m_prog->setRange(0, 1); m_prog->setValue(0); }
}

void MainWindow::cancelJob() {
    if (m_worker) m_worker->cancelInt = 1;
    log("canceling...");
}

void MainWindow::log(const QString &s) {
    for (const QString &line : s.split('\n')) m_log->appendPlainText(line);
}

void MainWindow::closeEvent(QCloseEvent *e) {
    if (m_busy) {
        if (QMessageBox::question(this, tr("Quit"), tr("A job is running. Quit anyway?")) != QMessageBox::Yes) { e->ignore(); return; }
        if (m_worker) { m_worker->cancelInt = 1; m_worker->wait(3000); }
    }
    QSettings s;
    s.setValue("x/backup", xBackup->text());
    s.setValue("x/out", xOut->text());
    s.setValue("c/source", cSource->text());
    s.setValue("c/out", cOut->text());
    s.setValue("c/tmpl", cTmpl->text());
    s.setValue("geom", saveGeometry());
    QMainWindow::closeEvent(e);
}
