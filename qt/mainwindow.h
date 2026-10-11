/* mainwindow.h - PS4 backup (P4BR / SCECAF) extractor + creator, Qt 6. */
#ifndef BAR_MAINWINDOW_H
#define BAR_MAINWINDOW_H

#include <QMainWindow>
#include <functional>

class QLineEdit;
class QCheckBox;
class QSpinBox;
class QComboBox;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QPlainTextEdit;
class Worker;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *) override;

private slots:
    void doExtract();
    void doCreate();
    void makeSkeleton();
    void autofillFromTemplate();
    void cancelJob();

private:
    QWidget *buildExtractTab();
    QWidget *buildCreateTab();
    void startJob(const QString &label, std::function<int()> body,
                  std::function<void(int)> done);
    void setBusy(bool busy, const QString &label);
    void log(const QString &s);

    /* extract tab */
    QLineEdit *xBackup, *xOut, *xKey, *xHash, *xInc, *xExc, *xManifest;
    QCheckBox *xVerify, *xList;
    QSpinBox  *xThreads;

    /* create tab */
    QLineEdit *cSource, *cOut, *cName, *cLabel, *cTmpl, *cUser, *cHost, *cPsid;
    QPlainTextEdit *cSets;
    QComboBox *cKeyset;
    QCheckBox *cVerify, *cClone;

    /* shared */
    QPlainTextEdit *m_log;
    QProgressBar   *m_prog;
    QPushButton    *m_cancel;
    Worker         *m_worker = nullptr;
    bool            m_busy = false;
};

#endif
