import threading
import requests
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def send_requests(thread_id, url, num_requests):
    for i in range(num_requests):
        try:
            response = requests.get(url, timeout=2)
            logging.info(f"Thread {thread_id} - Request {i+1}/{num_requests}: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Thread {thread_id} - Request {i+1}/{num_requests} failed: {e}")
        time.sleep(0.05)  # Increased delay to ensure capture
    logging.info(f"Thread {thread_id} - Completed {num_requests} requests")

def main():
    url = "http://192.168.0.100:8080/hybridaction/zybTrackerStatisticsAction"
    num_threads = 5
    requests_per_thread = 100
    total_requests = num_threads * requests_per_thread

    logging.info(f"Starting HTTP flood test against {url}")
    logging.info(f"Using {num_threads} threads with {requests_per_thread} requests each")
    logging.info(f"Total requests: {total_requests}")

    start_time = time.time()
    threads = []

    for i in range(num_threads):
        thread = threading.Thread(target=send_requests, args=(i+1, url, requests_per_thread))
        threads.append(thread)
        thread.start()
        logging.info(f"Started thread {i+1}/{num_threads}")
        time.sleep(0.1)  # Stagger thread starts

    for thread in threads:
        thread.join()
        logging.info("Thread completed")

    duration = time.time() - start_time
    rate = total_requests / duration
    logging.info(f"\nTest completed in {duration:.2f} seconds")
    logging.info(f"Average rate: {rate:.2f} requests/second")

if __name__ == "__main__":
    main()
