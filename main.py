from datetime import datetime
import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ------------------------------------------------------------------
# STRUKTUR BLOCK + FUNGSI HASH (KODE ASLI)
# ------------------------------------------------------------------
class laporanBlock:

  def __init__(
      self, id, tipeTransaksi, isi, actorId, parentId=None, parentHash=None
  ):
    self.id = id
    self.tipeTransaksi = tipeTransaksi
    self.isi = isi
    self.actorId = actorId
    self.parentId = parentId
    self.parentHash = parentHash
    self.timestamp = datetime.now().isoformat()
    self.signature = None


def hashTeks(teks):
  """SHA-256 dari string biasa (untuk demo sifat hash)."""
  return hashlib.sha256(teks.encode("utf-8")).hexdigest()


def computeHash(block):
  """SHA-256 dari isi block (tanpa signature)."""
  dataTanpaSignature = {
      k: v for k, v in block.__dict__.items() if k != "signature"
  }
  payload = json.dumps(dataTanpaSignature, sort_keys=True).encode("utf-8")
  return hashlib.sha256(payload).hexdigest()


def jumlahBitBeda(hash1, hash2):
  """Hitung berapa bit yang berbeda di antara dua hash SHA-256 (maks 256)."""
  return bin(int(hash1, 16) ^ int(hash2, 16)).count("1")


# Setup Kunci Kriptografi Validator (PoA)
privateKeyDinasPU = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)
publicKeyDinasPU = privateKeyDinasPU.public_key()

PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
)


def pesanBlock(block):
  dataTanpaSignature = {
      k: v for k, v in block.__dict__.items() if k != "signature"
  }
  return json.dumps(dataTanpaSignature, sort_keys=True).encode("utf-8")


def signBlock(block, privateKey):
  block.signature = privateKey.sign(pesanBlock(block), PSS, hashes.SHA256())


def verifyBlock(block, publicKey):
  if block.signature is None:
    return False
  try:
    publicKey.verify(block.signature, pesanBlock(block), PSS, hashes.SHA256())
    return True
  except Exception:
    return False


# ==================================================================
# EKSPERIMEN 1 - DATA DOMAIN KELOMPOK (LAYANAN PUBLIK)
# ==================================================================
print("=" * 70)
print("EKSPERIMEN 1 - Data Domain Kelompok & Penentuan Nilai Hash")
print("=" * 70)

# 1. Data History Block Asli (Layanan Publik)
laporan1 = laporanBlock(
    1, "LAPORAN_BARU", "Jalan Rusak di jalan maleo", "Warga01"
)
hashAsli = computeHash(laporan1)

print("Data History Block Asli   :", laporan1.isi)
print("Hash Block Asli           :", hashAsli)

# 2. Mengubah Isi History Block
laporan1.isi = "Jalan Rusak di jalan maleo SUDAH DIPERBAIKI"
hashSetelhaUbah = computeHash(laporan1)

print("\nData History Block Diubah :", laporan1.isi)
print("Hash Block Setelah Ubah   :", hashSetelhaUbah)
print(
    f"Perbedaan Jumlah Bit Hash : {jumlahBitBeda(hashAsli, hashSetelhaUbah)} bit"
)
print(
    "Kesimpulan                : Perubahan data domain ikut merubah nilai"
    " hash total secara signifikan."
)

# Balikkan data ke asli untuk eksperimen selanjutnya
laporan1.isi = "Jalan Rusak di jalan maleo"


# ==================================================================
# EKSPERIMEN 2 - FORK & RESOLVE CONFLICTS (LONGEST CHAIN RULE)
# ==================================================================
print("\n" + "=" * 70)
print("EKSPERIMEN 2 - Fork (2 Node Tanpa Peer & Resolve Chain)")
print("=" * 70)

# Genesis Block
b0 = laporanBlock(0, "GENESIS", "Genesis Laporan Warga", "System")

# Node 1: Menambang/Menandatangani 2 Block
n1_b1 = laporanBlock(
    1,
    "LAPORAN_BARU",
    "Lampu jalan padam di Sektor 1",
    "DinasPU",
    parentId=0,
    parentHash=computeHash(b0),
)
signBlock(n1_b1, privateKeyDinasPU)

n1_b2 = laporanBlock(
    2,
    "UPDATE_STATUS",
    "Pengecekan tim teknisi",
    "DinasPU",
    parentId=1,
    parentHash=computeHash(n1_b1),
)
signBlock(n1_b2, privateKeyDinasPU)

chain_node1 = {0: b0, 1: n1_b1, 2: n1_b2}

# Node 2: Menambang/Menandatangani 3 Block
n2_b1 = laporanBlock(
    1,
    "LAPORAN_BARU",
    "Pohon tumbang di Sektor 3",
    "DinasPU",
    parentId=0,
    parentHash=computeHash(b0),
)
signBlock(n2_b1, privateKeyDinasPU)

n2_b2 = laporanBlock(
    2,
    "UPDATE_STATUS",
    "Evakuasi pohon tumbang",
    "DinasPU",
    parentId=1,
    parentHash=computeHash(n2_b1),
)
signBlock(n2_b2, privateKeyDinasPU)

n2_b3 = laporanBlock(
    3,
    "TANGGAPAN_RESMI",
    "Pohon selesai dievakuasi",
    "DinasPU",
    parentId=2,
    parentHash=computeHash(n2_b2),
)
signBlock(n2_b3, privateKeyDinasPU)

chain_node2 = {0: b0, 1: n2_b1, 2: n2_b2, 3: n2_b3}

print(f"Panjang Rantai Node 1 : {len(chain_node1)} block (2 block setelah genesis)")
print(f"Panjang Rantai Node 2 : {len(chain_node2)} block (3 block setelah genesis)")


def resolve_conflicts(chain_a, chain_b):
  """Resolve rantai berdasarkan aturan Longest Chain Rule"""
  if len(chain_b) > len(chain_a):
    block_dibuang = [b for id_b, b in chain_a.items() if id_b != 0]
    return chain_b.copy(), block_dibuang
  return chain_a.copy(), []


print("\n[Menghubungkan Node 1 dan Node 2, lalu menjalankan Resolve...]")
chain_bertahan, block_dibuang = resolve_conflicts(chain_node1, chain_node2)

print("\nHasil Konsensus Fork:")
print(f"Rantai Bertahan  : Rantai milik Node 2 (Panjang {len(chain_bertahan)} block)")
print("Block Dibuang    (Orphaned Blocks dari Node 1):")
for b in block_dibuang:
  print(
      f"  - Block ID {b.id} | {b.tipeTransaksi:<15} | Actor: {b.actorId} |"
      f" Hash: {computeHash(b)[:16]}..."
  )


# ==================================================================
# EKSPERIMEN 3 - DIFFICULTY & KEAMANAN PENULISAN RIWAYAT (PoA)
# ==================================================================
print("\n" + "=" * 70)
print("EKSPERIMEN 3 - Keamanan Riwayat & Kompleksitas Verifikasi (PoA)")
print("=" * 70)

# Simulasi penulisan ulang riwayat oleh penyerang (Attacker)
laporan_palsu = laporanBlock(
    1,
    "LAPORAN_BARU",
    "Jalan Rusak di jalan maleo (Manipulasi)",
    "DinasPU",
    parentId=0,
    parentHash=computeHash(b0),
)

# Attacker mencoba menandatangani pakai key sembarang (Key Lain)
privateKeyLain = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signBlock(laporan_palsu, privateKeyLain)

print(
    "1. Validasi Signature Attacker pada Node Resmi:",
    verifyBlock(laporan_palsu, publicKeyDinasPU),
)

# Ukur beban verifikasi validator saat memeriksa integritas riwayat
start_time = time.time()
for _ in range(1000):
  verifyBlock(n2_b1, publicKeyDinasPU)
waktu_verifikasi = time.time() - start_time

print(
    f"2. Waktu Verifikasi 1.000 Signature Kriptografi Validator: {waktu_verifikasi:.4f} detik"
)
print(
    "\nAnalisis Keamanan Penulisan Ulang Riwayat (PoA):"
    "\n- Pada PoA, penulisan ulang riwayat gagal secara mutlak karena Attacker"
    " tidak memiliki Private Key milik DinasPU (validator resmi)."
    "\n- Perubahan 1 karakter saja akan membatalkan Signature RSA dan merusak"
    " keterkaitan parentHash pada rantai selanjutnya."
)