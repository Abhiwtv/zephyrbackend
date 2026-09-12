import os
import shutil
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

def backup_to_supabase():
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
    if not supabase_url or not supabase_key:
        print("[!] Missing Supabase credentials. Skipping backup.")
        return

    supabase: Client = create_client(supabase_url, supabase_key)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    zip_name = f"zephyr_training_logs_{timestamp}"
    zip_path = f"{zip_name}.zip"
    
    print(f"\n[BACKUP] Compressing {data_dir}...")
    shutil.make_archive(zip_name, 'zip', data_dir)
    
    print(f"[BACKUP] Uploading {zip_path} to Supabase bucket 'training_logs'...")
    try:
        with open(zip_path, "rb") as f:
            supabase.storage.from_("training_logs").upload(
                path=zip_path, 
                file=f, 
                file_options={"content-type": "application/zip"}
            )
        print("[BACKUP] Upload successful.")
    except Exception as e:
        print(f"[BACKUP] Failed to upload: {e}")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)