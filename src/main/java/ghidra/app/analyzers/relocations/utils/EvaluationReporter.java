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
package ghidra.app.analyzers.relocations.utils;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;

public class EvaluationReporter {
	private final class Report {
		final String format;
		final Object[] args;

		public Report(String type, boolean result, long destination, String format,
				Object... args) {
			this.format = "%c %-20s 0x%08x %c " + format;
			this.args = new Object[args.length + 4];
			this.args[0] = result ? '✅' : '❌';
			this.args[1] = type + ':';
			this.args[2] = destination;
			this.args[3] = result ? '=' : '≠';
			System.arraycopy(args, 0, this.args, 4, args.length);
		}

		public void dump(MessageLog log) {
			log.appendMsg(String.format(format, args));
		}
	}

	private final List<Report> reports = new ArrayList<>();

	public void add(String type, boolean result, long destination, String format, Object... args) {
		reports.add(new Report(type, result, destination, format, args));
	}

	public void clear() {
		reports.clear();
	}

	public void dump(MessageLog log) {
		for (Report report : reports) {
			report.dump(log);
		}
	}
}
