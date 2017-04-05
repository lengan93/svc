#ifndef TIMER_H
#define TIMER_H

#include <thread>
#include <chrono>

class Timer
{
public:
    typedef std::chrono::milliseconds Interval;
    typedef std::function<void(void*)> Timeout;

    // Timer(const Timeout &timeout, const void* args);
    // Timer(const Timeout &timeout, const void* args,
    //       const Interval &interval,
    //       bool singleShot = true);

    // void start(bool multiThread = false);
    // void stop();

    // bool running() const;

    // void setSingleShot(bool singleShot);
    // bool isSingleShot() const;

    // void setInterval(const Interval &interval);
    // const Interval &interval() const;

    // void setTimeout(const Timeout &timeout, const void* args);
    // const Timeout &timeout() const;

    Timer(const Timeout &timeout, void* args)
        : _timeout(timeout),
        _timeoutArgs(args)
    {
    }

    Timer(const Timeout &timeout, void* args,
                 const Interval &interval,
                 bool singleShot)
        : _isSingleShot(singleShot),
          _interval(interval),
          _timeout(timeout),
          _timeoutArgs(args)
    {
    }

    ~Timer() {
        this->stop();
        // delete _thread;
    }

    void start(bool multiThread)
    {
        if (this->running() == true)
            return;

        _running = true;

        if (multiThread == true) {
            _thread = new std::thread(
                        &_temporize, this);
        }
        else{
            this->_temporize(this);
        }
    }

    void stop()
    {
        _running = false;
        _thread->join();
    }

    bool running() const
    {
        return _running;
    }

    void setSingleShot(bool singleShot)
    {
        if (this->running() == true)
           return;

        _isSingleShot = singleShot;
    }

    bool isSingleShot() const
    {
        return _isSingleShot;
    }

    void setInterval(const Interval &interval)
    {
        if (this->running() == true)
           return;

        _interval = interval;
    }

    const Interval &interval() const
    {
        return _interval;
    }

    void setTimeout(const Timeout &timeout, void* args)
    {
        if (this->running() == true)
           return;

        _timeout = timeout;
        _timeoutArgs = args;
    }

    const Timeout &timeout() const
    {
        return _timeout;
    }

    
    // void setTimeoutArgs(void* args);

private:
    void* _timeoutArgs = nullptr;
    std::thread *_thread;

    bool _running = false; 
    bool _isSingleShot = true;

    Interval _interval = Interval(1000);
    Timeout _timeout = nullptr;

    // void _temporize();
    // void _sleepThenTimeout();

    static void _temporize(Timer* _this)
    {
        if (_this->_isSingleShot == true) {
            _this->_sleepThenTimeout();
        }
        else {
            while (_this->running() == true) {
                _this->_sleepThenTimeout();
            }
        }
    }

    void _sleepThenTimeout()
    {
        std::this_thread::sleep_for(_interval);

        if (this->running() == true)
            this->timeout()(_timeoutArgs);
    }
};

#endif