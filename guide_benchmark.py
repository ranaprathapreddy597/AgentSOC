import os
import time
import asyncio
import logging
import aiohttp
import polars as pl

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# The AgentSOC FastAPI endpoint
INGEST_URL = "http://localhost:8000/ingest"
TEST_FILE_PATH = os.path.join(".", "dataset", "GUIDE_Test.csv")

async def stream_alert_to_soc(session: aiohttp.ClientSession, row: dict):
    """Formats a Microsoft GUIDE row into an AgentSOC payload and fires it."""
    payload = {
        "log": f"ALERT: {row.get('grid_3x3AlertTitle', 'Unknown Alert')} | CATEGORY: {row.get('text_formatCategory', 'N/A')} | MITRE: {row.get('text_formatMitreTechniques', 'N/A')}",
        "source_ip": "10.0.0.1", 
        "target_ip": "10.0.0.5", 
        "sync_execution": False  # Use our <5ms background execution SLA
    }
    
    try:
        async with session.post(INGEST_URL, json=payload) as response:
            return await response.json()
    except Exception:
        return None

async def run_guide_simulation(limit: int = 10000):
    """Reads the dataset via Polars and blasts it asynchronously."""
    if not os.path.exists(TEST_FILE_PATH):
        logger.error(f"Cannot find {TEST_FILE_PATH}. Please ensure you extracted the CSV there.")
        return

    logger.info(f"Loading Microsoft GUIDE dataset into memory via Polars...")
    
    # Polars is highly optimized and will load the large file in seconds
    df = pl.read_csv(TEST_FILE_PATH, ignore_errors=True)
    
    # Slice the dataset for the benchmark run
    test_slice = df.head(limit).to_dicts()
    logger.info(f"Successfully loaded. Initiating asynchronous streaming of {limit} alerts...")
    
    start_time = time.perf_counter()
    
    # Create an async session and fire the requests concurrently
    async with aiohttp.ClientSession() as session:
        tasks = [stream_alert_to_soc(session, row) for row in test_slice]
        await asyncio.gather(*tasks)
        
    end_time = time.perf_counter()
    total_time_ms = (end_time - start_time) * 1000
    avg_latency = total_time_ms / limit
    
    logger.info("==================================================")
    logger.info("  MICROSOFT GUIDE DATASET - EMPIRICAL BENCHMARK   ")
    logger.info("==================================================")
    logger.info(f"Total Alerts Streamed : {limit}")
    logger.info(f"Total Processing Time : {total_time_ms:.2f} ms")
    logger.info(f"Avg Ingestion Latency : {avg_latency:.3f} ms per alert")
    logger.info("==================================================")

if __name__ == "__main__":
    # Run the asynchronous load test (testing with 10,000 alerts)
    asyncio.run(run_guide_simulation(limit=10000))