from data_processor import RansomwareLogProcessor

processor = RansomwareLogProcessor(
    nat_dir="data/NATscenario",
    original_dir="data/originalScenario"
)
results = processor.process_all()