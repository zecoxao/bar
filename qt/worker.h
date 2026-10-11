/* worker.h - runs a blocking bridge call on a background thread, marshaling
 * log / progress / completion to the GUI thread via queued signals. */
#ifndef BAR_WORKER_H
#define BAR_WORKER_H

#include <QThread>
#include <QString>
#include <functional>

class Worker : public QThread {
    Q_OBJECT
public:
    explicit Worker(QObject *parent = nullptr) : QThread(parent) { cancelInt = 0; }

    std::function<int()> job;      /* runs on this thread, returns rc */
    volatile int cancelInt;        /* bridges poll this; Cancel sets it to 1 */

    /* C trampolines (ud == Worker*) matching bar_log_fn / bar_prog_fn */
    static void logCb(const char *line, void *ud) {
        emit static_cast<Worker *>(ud)->logLine(QString::fromUtf8(line));
    }
    static void progCb(long long done, long long total, void *ud) {
        emit static_cast<Worker *>(ud)->progress((qint64)done, (qint64)total);
    }

signals:
    void logLine(QString line);
    void progress(qint64 done, qint64 total);
    void jobFinished(int rc);

protected:
    void run() override { int rc = job ? job() : -1; emit jobFinished(rc); }
};

#endif
