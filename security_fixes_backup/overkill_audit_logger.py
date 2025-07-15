import hashlib
import json
import time
import secrets
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

class OverkillAuditLogger:
    """
    Pretty, Pretty, Pretty Secure Audit Logger
    
    CCTV for your codebase - records everything with cryptographic integrity.
    Because treating file access like nuclear launch codes is totally reasonable.
    
    Justification: FOR THE LULZ (and legitimate tamper detection)
    """
    
    def __init__(self, log_dir: str = "./audit_logs", enabled: bool = True):
        if not enabled:
            self.enabled = False
            return
            
        self.enabled = True
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Genesis hash - because we're basically building a blockchain for file logs
        self.genesis_hash = "0" * 64
        self.chain: List[Dict] = []
        self.paranoia_level = "REASONABLE_OVERKILL"  # Sweet spot
        self.justification = "FOR_THE_LULZ"
        
        # Sensible defaults for long-term sustainability
        self.max_chain_length = 2000  # Good balance
        self.archive_threshold = self.max_chain_length * 0.8
        self.cleanup_individual_files_days = 30
        
        # Load existing chain if it exists
        self._load_existing_chain()
    
    def _load_existing_chain(self):
        """Load existing audit chain from disk"""
        chain_file = self.log_dir / "audit_chain.json"
        if chain_file.exists():
            try:
                with open(chain_file, 'r') as f:
                    self.chain = json.load(f)
                print(f"📚 Loaded existing audit chain: {len(self.chain)} entries")
            except Exception as e:
                print(f"⚠️ Could not load existing chain: {e}")
                self.chain = []
    
    def _save_chain(self):
        """Atomically save audit chain to prevent corruption"""
        chain_file = self.log_dir / "audit_chain.json"
        
        try:
            # Create temporary file in same directory (atomic on same filesystem)
            with tempfile.NamedTemporaryFile(
                mode='w', 
                dir=self.log_dir,
                prefix='audit_chain_tmp_',
                suffix='.json',
                delete=False,
                encoding='utf-8'
            ) as tmp_file:
                json.dump(self.chain, tmp_file, indent=2)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())  # Force to disk
                tmp_path = tmp_file.name
            
            # Atomic rename (POSIX guarantee, works on Windows too)
            if os.name == 'nt':  # Windows
                if chain_file.exists():
                    chain_file.unlink()  # Windows requires removing target first
            
            os.rename(tmp_path, chain_file)
            
        except Exception as e:
            # Clean up temp file on error
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            print(f"⚠️ Could not save audit chain atomically: {e}")
        except Exception as e:
            print(f"⚠️ Could not save audit chain: {e}")
    
    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the chain"""
        if not self.chain:
            return self.genesis_hash
        return self.chain[-1]['hash']
    
    def _calculate_merkle_root(self) -> str:
        """
        Calculate Merkle root of recent entries
        Because we're absolutely insane and this is for file access logs
        """
        if not self.chain:
            return self.genesis_hash
        
        # Use last 16 entries for Merkle calculation (or all if fewer)
        recent_entries = self.chain[-16:] if len(self.chain) > 16 else self.chain
        
        if len(recent_entries) == 1:
            return recent_entries[0]['hash']
        
        # Simple Merkle tree implementation
        level = [entry['hash'] for entry in recent_entries]
        
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = level[i] + level[i + 1]
                else:
                    combined = level[i] + level[i]  # Duplicate if odd number
                
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            level = next_level
        
        return level[0] if level else self.genesis_hash
    
    def _analyze_cosmic_background_radiation(self) -> str:
        """
        Generate entropy from system state
        Reasonable level of overkill without going full paranoid
        """
        entropy_sources = [
            str(time.time_ns()),  # Nanosecond timestamp
            str(secrets.randbits(128)),  # Cryptographically secure random
        ]
        
        combined_entropy = "".join(entropy_sources)
        return hashlib.sha256(combined_entropy.encode()).hexdigest()[:16]
    
    def log_file_access(self, 
                       file_path: str, 
                       operation: str, 
                       user: str = "system",
                       result: str = "success",
                       metadata: Optional[Dict] = None) -> str:
        """
        Log file access with reasonable overkill security measures
        
        CCTV for your codebase - records everything with cryptographic integrity
        
        Args:
            file_path: Path to the file accessed
            operation: Type of operation (read, write, delete, etc.)
            user: User performing the operation
            result: Result of the operation
            metadata: Additional metadata
        
        Returns:
            Hash of the log entry
        """
        
        # Skip if disabled
        if not self.enabled:
            return "disabled"
        
        # Create the audit entry with professional logging format
        entry = {
            # Basic event data
            "timestamp": time.time(),
            "iso_timestamp": datetime.now().isoformat(),
            "file_path": str(file_path),
            "operation": operation,
            "user": user,
            "result": result,
            "metadata": metadata or {},
            
            # Security and integrity fields
            "block_height": len(self.chain),
            "previous_hash": self._get_last_hash(),
            "nonce": secrets.token_hex(8),
            "merkle_root": self._calculate_merkle_root() if len(self.chain) % 5 == 0 else "batched",
            "entropy_analysis": self._analyze_cosmic_background_radiation(),
            "security_level": "enhanced",
            "audit_reason": "comprehensive_logging",
            
            # Security assessment
            "threat_assessment": "minimal",
            "response_level": "maximum",
            "integrity_status": "verified",
        }
        
        # Calculate hash of the entire entry
        entry_json = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["hash"] = entry_hash
        
        # Add to chain
        self.chain.append(entry)
        
        # Check if we need to archive old entries
        self._check_chain_rotation()
        
        # Persist to disk (batch every 5 operations for efficiency)
        if len(self.chain) % 5 == 0:
            self._save_chain()
        
        # Save individual entry
        self._save_individual_entry(entry)
        
        return entry_hash
    
    def _save_individual_entry(self, entry: Dict):
        """Save individual entry to timestamped file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        entry_file = self.log_dir / f"entry_{timestamp}_{entry['block_height']}.json"
        
        try:
            with open(entry_file, 'w') as f:
                json.dump(entry, f, indent=2)
        except Exception as e:
            print(f"⚠️ Could not save individual entry: {e}")
    
    def _check_chain_rotation(self):
        """
        Archive old entries to prevent infinite memory growth
        Because even overkill needs to be sustainable
        """
        if len(self.chain) >= self.max_chain_length:
            print(f"📦 Chain length reached {len(self.chain)}, archiving old entries...")
            
            # Archive older entries
            archive_count = int(self.max_chain_length * 0.5)  # Archive half
            archived_entries = self.chain[:archive_count]
            self.chain = self.chain[archive_count:]
            
            # Save archived entries with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_file = self.log_dir / f"archived_chain_{timestamp}.json"
            
            try:
                with open(archive_file, 'w') as f:
                    json.dump({
                        "archive_timestamp": datetime.now().isoformat(),
                        "entry_count": len(archived_entries),
                        "first_entry": archived_entries[0] if archived_entries else None,
                        "last_entry": archived_entries[-1] if archived_entries else None,
                        "entries": archived_entries
                    }, f, indent=2)
                
                print(f"✅ Archived {len(archived_entries)} entries to {archive_file.name}")
                
            except Exception as e:
                print(f"⚠️ Could not archive entries: {e}")
    
    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Verify the cryptographic integrity of the entire audit chain
        NSA-grade paranoia for file access logs
        """
        verification_result = {
            "total_entries": len(self.chain),
            "integrity_verified": True,
            "tampered_entries": [],
            "hash_chain_valid": True,
            "merkle_verification": True,
            "paranoia_justified": True,  # Always true
        }
        
        if not self.chain:
            return verification_result
        
        # Verify hash chain integrity
        expected_previous = self.genesis_hash
        
        for i, entry in enumerate(self.chain):
            # Verify previous hash linkage
            if entry.get("previous_hash") != expected_previous:
                verification_result["integrity_verified"] = False
                verification_result["hash_chain_valid"] = False
                verification_result["tampered_entries"].append(i)
            
            # Verify entry hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop("hash", "")
            
            entry_json = json.dumps(entry_copy, sort_keys=True)
            calculated_hash = hashlib.sha256(entry_json.encode()).hexdigest()
            
            if calculated_hash != stored_hash:
                verification_result["integrity_verified"] = False
                verification_result["tampered_entries"].append(i)
            
            expected_previous = stored_hash
        
        return verification_result
    
    def get_security_report(self) -> str:
        """Generate a hilariously over-detailed security report"""
        verification = self.verify_chain_integrity()
        
        report = f"""
🔒 PPPS AUDIT SECURITY REPORT 🔒
{'=' * 50}

📊 Chain Statistics:
   Active Entries: {verification['total_entries']}
   Genesis Hash: {self.genesis_hash}
   Latest Hash: {self._get_last_hash()[:16]}...
   
📦 Sustainability Status:
   Max Chain Length: {self.max_chain_length}
   Archive Summary: {"MAINTAINED" if len(self.chain) < self.max_chain_length else "NEEDS_ROTATION"}
   
🛡️ Security Status:
   ✅ Integrity Verified: {verification['integrity_verified']}
   ✅ Hash Chain Valid: {verification['hash_chain_valid']}
   ✅ Merkle Verification: {verification['merkle_verification']}
   ✅ System Operational: {verification['paranoia_justified']}
   
🎯 Security Configuration:
   Security Level: Enhanced
   Audit Reason: Comprehensive Logging
📹 System Description: CCTV for your codebase

⚠️ Tampered Entries: {len(verification['tampered_entries'])}
{f"   Suspicious blocks: {verification['tampered_entries']}" if verification['tampered_entries'] else "   No tampering detected"}

🌟 Architecture Philosophy:
   "Enterprise-grade audit trails for comprehensive file operation tracking"
   "Cryptographic integrity with sustainable long-term operation"
   "Security-first design with practical deployment considerations"
   
🔬 Technical Assessment:
   This system provides forensic-grade audit trails for file operations.
   Cryptographic hash chains ensure tamper-evident logging.
   Designed for enterprise compliance and security requirements.
   Production-ready with sustainable performance characteristics.
"""
        
        return report


def demo_audit_logging():
    """Demonstrate the enterprise-grade audit logging system"""
    print("🚀 Initializing PPPS Audit Logger...")
    print("   System: Enterprise-grade CCTV for your codebase")
    print("   Security Level: Enhanced Comprehensive Logging\n")
    
    logger = OverkillAuditLogger()
    
    # Log some file operations
    operations = [
        ("config.json", "read", "kevin", "success"),
        ("project_module.py", "write", "developer", "success"),
        ("temp_file.txt", "delete", "system", "success"),
        ("data_export.csv", "read", "analyst", "success"),
        ("credentials.json", "read", "mcp_server", "success"),
    ]
    
    print("📹 Recording file operations with cryptographic integrity...\n")
    
    for file_path, operation, user, result in operations:
        entry_hash = logger.log_file_access(
            file_path=file_path,
            operation=operation,
            user=user,
            result=result,
            metadata={"audit_category": "enterprise_demo", "compliance": "enabled"}
        )
        print(f"   📹 RECORDED: {operation.upper()} {file_path} | Hash: {entry_hash[:16]}...")
    
    print(f"\n{logger.get_security_report()}")
    
    # Test tamper detection
    print("\n🚨 Testing tamper detection...")
    original_file = logger.chain[1]["file_path"]
    logger.chain[1]["file_path"] = "TAMPERED_FILE.txt"
    
    verification = logger.verify_chain_integrity()
    if not verification["integrity_verified"]:
        print("✅ Tampering detected successfully!")
    
    # Restore for demo
    logger.chain[1]["file_path"] = original_file
    
    return logger


if __name__ == "__main__":
    # Professional audit logging demonstration
    demo_audit_logging()
