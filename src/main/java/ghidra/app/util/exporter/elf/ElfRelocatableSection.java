/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.exporter.elf;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;

public abstract class ElfRelocatableSection implements ByteArrayConverter, Writeable {
	private final ElfRelocatableObject elf;
	private final String name;
	private final AddressSetView addressSet;
	protected int index;

	public ElfRelocatableSection(ElfRelocatableObject elf, String name) {
		this(elf, name, null);
	}

	public ElfRelocatableSection(ElfRelocatableObject elf, String name, AddressSetView addressSet) {
		this.elf = elf;
		this.name = name;
		this.addressSet = addressSet;
	}

	public ElfRelocatableObject getElfRelocatableObject() {
		return elf;
	}

	public int getIndex() {
		return index;
	}

	public String getName() {
		return name;
	}

	public long getOffset(Address address) {
		Address minAddress = addressSet.getMinAddress();
		AddressSetView intersectedRange = addressSet.intersectRange(minAddress, address);
		return intersectedRange.getNumAddresses() - 1;
	}

	public int getShName() {
		ElfRelocatableSectionStringTable shstrtab = elf.getShStrTab();
		if (shstrtab != null) {
			return shstrtab.indexOf(name);
		}

		return 0;
	}

	public abstract int getShType();

	public long getShFlags() {
		return 0;
	}

	public long getShAddr() {
		return 0;
	}

	public long getShOffset() {
		return elf.getOffsetOf(this);
	}

	public abstract long getShSize();

	public int getShLink() {
		return ElfSectionHeaderConstants.SHN_UNDEF;
	}

	public int getShInfo() {
		return 0;
	}

	public abstract long getShAddrAlign();

	public long getShEntSize() {
		return 0;
	}

	@Override
	public byte[] toBytes(DataConverter dc) throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(os);

		dos.write(dc.getBytes(getShName()));
		dos.write(dc.getBytes(getShType()));

		if (getElfRelocatableObject().is32Bit()) {
			dos.write(dc.getBytes((int) getShFlags()));
			dos.write(dc.getBytes((int) getShAddr()));
			dos.write(dc.getBytes((int) getShOffset()));
			dos.write(dc.getBytes((int) getShSize()));
		}
		else if (getElfRelocatableObject().is64Bit()) {
			dos.write(dc.getBytes(getShFlags()));
			dos.write(dc.getBytes(getShAddr()));
			dos.write(dc.getBytes(getShOffset()));
			dos.write(dc.getBytes(getShSize()));
		}
		else {
			throw new NotYetImplementedException();
		}

		dos.write(dc.getBytes(getShLink()));
		dos.write(dc.getBytes(getShInfo()));

		if (getElfRelocatableObject().is32Bit()) {
			dos.write(dc.getBytes((int) getShAddrAlign()));
			dos.write(dc.getBytes((int) getShEntSize()));
		}
		else if (getElfRelocatableObject().is64Bit()) {
			dos.write(dc.getBytes(getShAddrAlign()));
			dos.write(dc.getBytes(getShEntSize()));
		}
		else {
			throw new NotYetImplementedException();
		}

		return os.toByteArray();
	}
}
