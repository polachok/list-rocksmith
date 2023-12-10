import os
import struct
import codecs
import zlib
import sys
import json
import typing
import csv

from Crypto.Cipher import AES
from Crypto.Util import Counter

ENTRY_SIZE = 30
BLOCK_SIZE = 65536

ARC_KEY = 'C53DB23870A1A2F71CAE64061FDD0E1157309DC85204D4C5BFDF25090DF2572C'
ARC_IV = 'E915AA018FEF71FC508132E4BB4CEB42'

MAC_KEY = '9821330E34B91F70D0A48CBD625993126970CEA09192C0E6CDA676CC9838289D'
PC_KEY = 'CB648DF3D12A16BF71701414E69619EC171CCA5D2A142E3E59DE7ADDA18A3A30'

def pad(data, blocksize=16):
    """Zeros padding"""
    #So we need zeroes in order to match AES's encoding scheme which breaks
    #the data into 16-byte chunks. If we have 52 bytes to decode, then we have
    #3 full 16-byte blocks, and 4 left over. This means we need 12 bytes worth
    #of padding. That means we get 12 bytes worth of zeroes.
    padding = (blocksize - len(data)) % blocksize
    #Modify this to return a bytes object, since that's what pycrypto needs.
    return data + bytes(padding)

def cipher_toc():
    """AES CFB Mode"""
    return AES.new(codecs.decode(ARC_KEY,'hex'), mode=AES.MODE_CFB,
                   IV=codecs.decode(ARC_IV,'hex'), segment_size=128)

def aes_ctr(data, key, ivector, encrypt=True):
    """AES CTR Mode"""
    output = bytes()
    #First param: Number of bits of the cipher. 64 is not meaningful.
    ctr = Counter.new(64, initial_value = ivector)
    cipher = AES.new(codecs.decode(key,'hex'), mode=AES.MODE_CTR, counter=ctr)

    if encrypt:
        output += cipher.encrypt(pad(data))
    else:
        output += cipher.decrypt(pad(data))

    return output

def read_toc(filestream):
    """Read entry list and Z-fragments.
    Returns a list of entries to be used with read_entry."""

    entries = []
    zlength = []

    filestream.seek(0)
    header = struct.unpack('>4sL4sLLLLL', filestream.read(32))

    toc_size = header[3] - 32
    n_entries = header[5]
    toc = cipher_toc().decrypt(pad(filestream.read(toc_size)))
    toc_position = 0

    idx = 0
    while idx < n_entries:
        data = toc[toc_position:toc_position + ENTRY_SIZE]

        entries.append({
            'md5': data[:16],
            'zindex': struct.unpack('>L', data[16:20])[0],
            'length': struct.unpack('>Q', b'\x00'*3 + data[20:25])[0],
            'offset': struct.unpack('>Q', b'\x00'*3 + data[25:])[0]
        })
        toc_position += ENTRY_SIZE
        idx += 1

    idx = 0
    while idx < (toc_size - ENTRY_SIZE * n_entries) / 2:
        data = toc[toc_position:toc_position + 2]
        zlength.append(struct.unpack('>H', data)[0])
        toc_position += 2
        idx += 1

    for entry in entries:
        entry['zlength'] = zlength[entry['zindex']:]

    # Process the first entry as it contains the file listing
    entries[0]['filepath'] = ''
    filepaths = read_entry(filestream, entries[0]).split()
    for entry, filepath in zip(entries[1:], filepaths):
        entry['filepath'] = filepath.decode("utf-8")

    return entries[1:]

def read_entry(filestream, entry):
    """Extract zlib for one entry"""
    data = bytes()

    length = entry['length']
    zlength = entry['zlength']
    filestream.seek(entry['offset'])

    i = 0
    while len(data) < length:
        if zlength[i] == 0:
            data += filestream.read(BLOCK_SIZE)
        else:
            chunk = filestream.read(zlength[i])
            try:
                data += zlib.decompress(chunk)
            except zlib.error:
                data += chunk
        i += 1

    return data

class Track(typing.NamedTuple):
    artist: str
    album: str
    title: str
    arrangement: str
    tuning: str

class Tuning(typing.NamedTuple):
    string0: int
    string1: int
    string2: int
    string3: int
    string4: int
    string5: int

    @classmethod
    def standard(cls):
        return cls(0, 0, 0, 0, 0, 0)

    @classmethod
    def drop_d(cls):
        return cls(-2, 0, 0, 0, 0, 0)

    @classmethod
    def drop_c_sharp(cls):
        return cls(-3, -1, -1, -1, -1, -1)

    @classmethod
    def drop_c(cls):
        return cls(-4, -2, -2, -2, -2, -2)

    @classmethod
    def eb(cls):
        return cls(-1, -1, -1, -1, -1, -1)

    @classmethod
    def d(cls):
        return cls(-2, -2, -2, -2, -2, -2)

    @classmethod
    def c_sharp(cls):
        return cls(-3, -3, -3, -3, -3, -3)

    @classmethod
    def c(cls):
        return cls(-4, -4, -4, -4, -4, -4)

    @classmethod
    def b(cls):
        return cls(-5, -5, -5, -5, -5, -5)

    @classmethod
    def f(cls):
        return cls(1, 1, 1, 1, 1, 1)

    def __str__(self):
        if self == Tuning.standard():
            return "Standard"
        elif self == Tuning.drop_d():
            return "Drop D"
        elif self == Tuning.drop_c_sharp():
            return "Drop C#"
        elif self == Tuning.drop_c():
            return "Drop C"
        elif self == Tuning.eb():
            return "Lowered Eb"
        elif self == Tuning.d():
            return "Lowered D"
        elif self == Tuning.c_sharp():
            return "Lowered C#"
        elif self == Tuning.c():
            return "Lowered C"
        elif self == Tuning.b():
            return "Lowered B"
        elif self == Tuning.f():
            return "Raised F"
        else:
            return "Custom: {} {} {} {} {} {}".format(self.string0, self.string1, self.string2, self.string3, self.string4, self.string5)

def read_psarc(filename):
    tracks = set()
    with open(filename, 'rb') as psarc:
        entries = []
        try:
            entries = read_toc(psarc):
        except e:
            print("Error reading {}: {}".format(filename, e))
        for entry in entries:
            data = read_entry(psarc, entry)
            if entry['filepath'].endswith('.hsan'):
                data = json.loads(data)
                for key, value in data['Entries'].items():
                    attributes = value['Attributes']
                    if 'ArtistName' in attributes and 'AlbumName' in attributes and 'SongName' in attributes:
                        arrangement = attributes['ArrangementName']
                        tuning = Tuning(**attributes['Tuning'])
                        track = Track(attributes['ArtistName'], attributes['AlbumName'], attributes['SongName'], arrangement, str(tuning))
                        tracks.add(track)
    return tracks

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: psarc.py <directory>')
        sys.exit(1)
    filename = os.path.basename(sys.argv[1])
    f = open(filename + '.txt', 'w', newline = '', encoding='utf-8')
    writer = csv.DictWriter(f, fieldnames = ['artist', 'album', 'title', 'arrangement', 'tuning'])
    writer.writeheader()
    for root, dirs, files in os.walk(sys.argv[1]):
        for filename in files:
            if filename.endswith('.psarc'):
                tracks = read_psarc(os.path.join(root, filename))
                for track in tracks:
                    #print(track)
                    writer.writerow(track._asdict())
