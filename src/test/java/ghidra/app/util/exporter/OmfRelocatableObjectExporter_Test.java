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
package ghidra.app.util.exporter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import net.boricj.bft.omf.records.OmfRecordPubdef.PublicSymbol;

public class OmfRelocatableObjectExporter_Test {
	@Test
	public void testRejectDuplicateExternalNames() {
		MessageLog log = new MessageLog();
		List<String> names = List.of("_duplicate", "_duplicate");

		assertFalse(OmfRelocatableObjectExporter.validateUniqueExternalNames(names,
			log));
	}

	@Test
	public void testAcceptUniqueExternalNames() {
		MessageLog log = new MessageLog();
		List<String> names = List.of("___org__streams", "__streams");

		assertTrue(OmfRelocatableObjectExporter.validateUniqueExternalNames(names, log));
	}

	@Test
	public void testRejectDuplicatePublicNames() {
		MessageLog log = new MessageLog();
		List<PublicSymbol> publicSymbols = List.of(
			new PublicSymbol("_duplicate", 0, 0),
			new PublicSymbol("_duplicate", 4, 0));

		assertFalse(OmfRelocatableObjectExporter.validateUniquePublicNames(publicSymbols,
			log));
	}

	@Test
	public void testAcceptUniquePublicNames() {
		MessageLog log = new MessageLog();
		List<PublicSymbol> publicSymbols = List.of(
			new PublicSymbol("_first", 0, 0),
			new PublicSymbol("_second", 4, 0));

		assertTrue(OmfRelocatableObjectExporter.validateUniquePublicNames(publicSymbols,
			log));
	}
}