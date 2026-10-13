"""GDS Agent Kernel Daemon — Entry point for supervisor."""
import asyncio
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/gds-kernel.log'),
    ]
)

logger = logging.getLogger("gds.kernel.daemon")

async def main():
    from gds_kernel.kernel_executor import initialize_kernel_with_executors
    from gds_kernel.tool_wiring import wire_real_tools, test_wired_tools

    kernel = initialize_kernel_with_executors()

    # Wire real tool executors (replaces placeholder lambdas)
    wired = wire_real_tools(kernel)
    logger.info(f"Wired {wired} real tool executors")

    # Quick smoke test
    logger.info("Running tool smoke tests...")
    test_results = await test_wired_tools(kernel)
    for tool_id, result in test_results.items():
        status = result.get("status", "unknown")
        logger.info(f"  {tool_id}: {status}")
    logger.info("GDS Agent Kernel daemon started with real tools")

    # Main kernel loop
    while True:
        try:
            result = await kernel.run_cycle()
            if result["dispatched"] > 0:
                logger.info(f"Cycle {result['cycle']}: dispatched {result['dispatched']} processes")
            await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            break
        except Exception as e:
            logger.error(f"Kernel cycle error: {e}", exc_info=True)
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
