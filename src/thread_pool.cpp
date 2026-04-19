#include "thread_pool.hpp"
#include "logger.hpp"

namespace dns {

ThreadPool::ThreadPool(size_t threads) : stop_(false) {
    LOG_INFO("Initializing ThreadPool with " << threads << " threads");
    for (size_t i = 0; i < threads; ++i) {
        workers_.emplace_back(&ThreadPool::worker_thread, this);
    }
}

ThreadPool::~ThreadPool() {
    LOG_INFO("Shutting down ThreadPool");
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();

    for (std::thread &worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    LOG_INFO("ThreadPool shutdown complete");
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            return;
        }
        tasks_.push(std::move(task));
    }
    condition_.notify_one();
}

void ThreadPool::worker_thread() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(this->queue_mutex_);
            this->condition_.wait(lock, [this] {
                // Wait until the pool is stopped or there is a task to process
                return this->stop_ || !this->tasks_.empty();
            });

            if (this->stop_ && this->tasks_.empty()) {
                return;
            }

            task = std::move(this->tasks_.front());
            this->tasks_.pop();
        }

        // Execute the task
        task();
    }
}

} // namespace dns
