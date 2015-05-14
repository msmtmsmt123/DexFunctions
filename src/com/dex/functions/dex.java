/**
 * 此程序可以找出Dex文件中函数的调用序列
 */
package com.dex.functions;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;

class DexStringTable {
	public byte[] stringDataOff = new byte[4];
}

class DexTypeTable {
	public byte[] descriptorIdx = new byte[4]; // 指向DexStringIds列表的索引
}

class DexProtos {
	public byte[] shortIdx = new byte[4];
	public byte[] returnTypeIdx = new byte[4];
	public byte[] parametersOff = new byte[4];

	public byte[] sizeArray = new byte[4];
	public int size;
	public byte[] typeidx = new byte[size * 2];
}

class DexFieldTable {
	public byte[] classIdx = new byte[2];
	public byte[] typeIdx = new byte[2];
	public byte[] nameIdx = new byte[4];
}

class DexMethodTable {
	public byte[] classIdx = new byte[2];
	public byte[] protoIdx = new byte[2];
	public byte[] nameIdx = new byte[4];
}

class DexClassDefTable {
	public byte[] classIdx = new byte[4];
	public byte[] accessFlags = new byte[4];
	public byte[] superclassIdx = new byte[4];
	public byte[] interfacesOff = new byte[4];
	public byte[] sourceFileIdx = new byte[4];
	public byte[] annotationsOff = new byte[4];
	public byte[] classDataOff = new byte[4];
	public byte[] staticValuesOff = new byte[4];
}

class DexField {
	// 在dex文件中此处为uleb128编码
	public byte[] fieldIdx = new byte[4];
	public int fieldIdxValue;
	public byte[] accessFlags = new byte[4];
	public int accessFlagsValue;
}

class DexMethod {
	// 在dex文件中此处为uleb128编码
	public byte[] methodIdx = new byte[4];
	public int methodIdxValue;
	public byte[] accessFlags = new byte[4];
	public int accessFlagsValue;
	public byte[] codeOff = new byte[4];
	public int codeOffValue;
}

class DexClassDataHeader {
	// 在dex文件中此处为uleb128编码
	public int staticFieldsSize;
	public int instanceFieldsSize;
	public int directMethodsSize;
	public int virualMethodsSize;
}

class DexCode {
	public byte[] registersSize = new byte[2];
	public byte[] insSize = new byte[2];
	public byte[] outsSize = new byte[2];
	public byte[] triesSize = new byte[2];
	public byte[] debugInfoOff = new byte[4];
	public byte[] insnsSize = new byte[4];
	// 指令集结构
}

public class dex {

	static class DexHeader {
		public static byte[] magic = new byte[8];
		public static byte[] checksum = new byte[4];
		public static byte[] signature = new byte[20];
		public static byte[] file_size = new byte[4];
		public static byte[] header_size = new byte[4];
		public static byte[] endian_tag = new byte[4];
		public static byte[] link_size = new byte[4];
		public static byte[] link_off = new byte[4];
		public static byte[] map_off = new byte[4];
		public static byte[] string_ids_size = new byte[4];
		public static byte[] string_ids_off = new byte[4];
		public static byte[] type_ids_size = new byte[4];
		public static byte[] type_ids_off = new byte[4];
		public static byte[] proto_ids_size = new byte[4];
		public static byte[] proto_ids_off = new byte[4];
		public static byte[] field_ids_size = new byte[4];
		public static byte[] field_ids_off = new byte[4];
		public static byte[] method_ids_size = new byte[4];
		public static byte[] method_ids_off = new byte[4];
		public static byte[] class_defs_size = new byte[4];
		public static byte[] class_defs_off = new byte[4];
		public static byte[] data_size = new byte[4];
		public static byte[] data_off = new byte[4];
	}

	// 访问标识 accessFlags
	public static HashMap<Long, String> accessFlags = new HashMap<Long, String>() {
		{
			put((long) 0x1, "ACC_PUBLIC");
			put((long) 0x2, "ACC_PRIVATE");
			put((long) 0x4, "ACC_PROTECTED");
			put((long) 0x8, "ACC_STATIC");
			put((long) 0x10, "ACC_FINAL");
			put((long) 0x20, "ACC_SYNCHRONIZED");
			put((long) 0x40, "ACC_BRIDGE");
			put((long) 0x80, "ACC_VARARGS");
			put((long) 0x100, "ACC_NATIVE");
			put((long) 0x200, "ACC_INTERFACE");
			put((long) 0x400, "ACC_ABSTRACT");
			put((long) 0x800, "ACC_STRICT");
			put((long) 0x1000, "ACC_SYNTHETIC");
			put((long) 0x2000, "ACC_ANNOTATION");
			put((long) 0x4000, "ACC_ENUM");
			put((long) 0x8000, "unused");
			put((long) 0x10000, "ACC_CONSTRUCTOR");
			put((long) 0x20000, "ACC_DECLARED_SYNCHRONIZED");
		}
	};

	public static void main(String[] args) {
		// 以字节形式读取dex文件
		File sourceDEXFile = new File("G:/DexInfo.dex");
		byte[] sourceDEXFileArray = readFileBytes(sourceDEXFile);

		// DexHeader赋值
		DexHeader dexHeader = new DexHeader();
		fillDexHeader(dexHeader, sourceDEXFileArray);
		printDexHeader(dexHeader);

		// 获取dex文件中所有的字符串
		int numOfStrings = byteArraytoInt(dexHeader.string_ids_size); // 共有多少个字符串
		String[] dexStrings = new String[numOfStrings];
		DexStringTable[] stringTable = new DexStringTable[numOfStrings];
		getDexStrings(dexStrings, stringTable, dexHeader, sourceDEXFileArray);
		System.out.println("Those strings in dex file are blow:");
		// 打印出字符串测试是否正确
		for (int i = 0; i < dexStrings.length; i++) {
			System.out.println("dexStrings[" + i + "]=" + dexStrings[i]);
		}

		// 获取dex文件中所有的数据类型
		int numOfTypes = byteArraytoInt(dexHeader.type_ids_size);
		String[] dexTypes = new String[numOfTypes];
		getDexTypes(dexTypes, dexStrings, dexHeader, sourceDEXFileArray);
		System.out.println("\n\nThose types in dex file are blow:");
		for (int i = 0; i < dexTypes.length; i++) {
			System.out.println("dexTypes[" + i + "]=:" + dexTypes[i]);
		}

		// 获取dex文件中所有的函数声明信息
		int numOfProtos = byteArraytoInt(dexHeader.proto_ids_size);
		String[] dexProtos = new String[numOfProtos];
		DexProtos[] protosTable = new DexProtos[numOfProtos];
		getDexProtos(dexProtos, dexStrings, dexTypes, protosTable, dexHeader,
				sourceDEXFileArray);
		System.out.println("\n\ndexProtos String are below:");
		for (int i = 0; i < numOfProtos; i++) {
			System.out.println("dexProtos[" + i + "]=" + dexProtos[i]);
		}

		// 获取dex文件中所有的字段信息
		int numOfFields = byteArraytoInt(dexHeader.field_ids_size);
		String[] dexFields = new String[numOfFields];
		DexFieldTable[] fieldsTable = new DexFieldTable[numOfFields];
		getDexFields(dexFields, fieldsTable, dexStrings, dexTypes, dexHeader,
				sourceDEXFileArray);
		System.out.println("\n\ndexFields String are below:");
		for (int i = 0; i < numOfFields; i++) {
			System.out.println("dexFields[" + i + "]=" + dexFields[i]);
		}

		// 获取dex文件中所有的函数信息
		int numOfMethods = byteArraytoInt(dexHeader.method_ids_size);
		String[] dexMethods = new String[numOfMethods];
		DexMethodTable[] methodsTable = new DexMethodTable[numOfMethods];
		getDexMethods(dexMethods, methodsTable, dexStrings, dexTypes,
				protosTable, dexHeader, sourceDEXFileArray);
		System.out.println("\n\ndexMethods String are below:");
		for (int i = 0; i < numOfMethods; i++) {
			System.out.println("dexMethods[" + i + "]=" + dexMethods[i]);
		}

		// 获取dex文件中所有的类信息，包括类名、标识、字段、方法
		int numOfClasses = byteArraytoInt(dexHeader.class_defs_size);
		DexClassDefTable[] classDefsTable = new DexClassDefTable[numOfClasses];
		getDexClasses(classDefsTable, dexStrings, dexTypes, fieldsTable,
				methodsTable, dexProtos, dexHeader, sourceDEXFileArray);

	}

	public static void getDexClasses(DexClassDefTable[] classDefsTable,
			String[] dexStrings, String[] dexTypes,
			DexFieldTable[] fieldsTable, DexMethodTable[] methodsTable,
			String[] dexProtos, DexHeader dexHeader, byte[] sourceDEXFileArray) {
		int numOfClasses = byteArraytoInt(dexHeader.class_defs_size);
		int offSetOfClassDefTable = byteArraytoInt(dexHeader.class_defs_off);

		DexClassDataHeader[] dexClassDataHeader = new DexClassDataHeader[numOfClasses];

		System.out.println("\n\n");
		// 获取DexClassDefTable中的类定义信息
		for (int i = 0; i < numOfClasses; i++) {

			// 获取classDefsTable表中关于类定义信息的内容
			classDefsTable[i] = new DexClassDefTable();

			classDefsTable[i].classIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfClassDefTable + i * 32, offSetOfClassDefTable + i
							* 32 + 4);
			classDefsTable[i].accessFlags = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 4,
					offSetOfClassDefTable + i * 32 + 8);
			classDefsTable[i].superclassIdx = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 8,
					offSetOfClassDefTable + i * 32 + 12);
			classDefsTable[i].interfacesOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 12,
					offSetOfClassDefTable + i * 32 + 16);
			classDefsTable[i].sourceFileIdx = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 16,
					offSetOfClassDefTable + i * 32 + 20);
			classDefsTable[i].annotationsOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 20,
					offSetOfClassDefTable + i * 32 + 24);
			classDefsTable[i].classDataOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 24,
					offSetOfClassDefTable + i * 32 + 28);
			classDefsTable[i].staticValuesOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfClassDefTable + i * 32 + 28,
					offSetOfClassDefTable + i * 32 + 32);

			// 打印出类的名字
			long flags;
			int sourceFileIdxIndex;
			int classIdxIndex;
			flags = byteArraytoInt(classDefsTable[i].accessFlags);
			sourceFileIdxIndex = byteArraytoInt(classDefsTable[i].sourceFileIdx);
			classIdxIndex = byteArraytoInt(classDefsTable[i].classIdx);

			System.out.println("The class is:" + accessFlags.get(flags) + " "
					+ dexTypes[classIdxIndex]);

			// 以下获取类的方法和字段
			int changeOffset = 0; // 记录每一次前进的偏移

			changeOffset = byteArraytoInt(classDefsTable[i].classDataOff);
			dexClassDataHeader[i] = new DexClassDataHeader();

			Integer[] tempValue = new Integer[4];
			int offsetPer = 0;
			for (int m = 0; m < 4; m++) {
				tempValue[m] = readUnsignedLeb128(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));
			}
			dexClassDataHeader[i].staticFieldsSize = tempValue[0];
			dexClassDataHeader[i].instanceFieldsSize = tempValue[1];
			dexClassDataHeader[i].directMethodsSize = tempValue[2];
			dexClassDataHeader[i].virualMethodsSize = tempValue[3];

			// 创建DexField和 DexMethod对象 应该创建成全局
			final DexField[] staticDexField = new DexField[dexClassDataHeader[i].staticFieldsSize];
			final DexField[] instanceDexField = new DexField[dexClassDataHeader[i].instanceFieldsSize];
			final DexMethod[] directDexMethod = new DexMethod[dexClassDataHeader[i].directMethodsSize];
			final DexMethod[] virualDexMethod = new DexMethod[dexClassDataHeader[i].virualMethodsSize];

			if (dexClassDataHeader[i].staticFieldsSize > 0) {
				System.out.println("It's static fields info is:");
				System.out
						.println("classType  accessFlag  fieldType  fieldName");
			}
			// staticField
			for (int m = 0; m < dexClassDataHeader[i].staticFieldsSize; m++) {
				staticDexField[m] = new DexField();

				staticDexField[m].fieldIdxValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				staticDexField[m].accessFlagsValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				int classIdxValue = byteArraytoInt(fieldsTable[staticDexField[m].fieldIdxValue].classIdx);
				int typeIdxValue = byteArraytoInt(fieldsTable[staticDexField[m].fieldIdxValue].typeIdx);
				int nameIdxValue = byteArraytoInt(fieldsTable[staticDexField[m].fieldIdxValue].nameIdx);

				System.out.println(dexTypes[classIdxValue] + "  "
						+ accessFlags.get(staticDexField[m].accessFlagsValue)
						+ "  " + dexTypes[typeIdxValue] + "  "
						+ dexStrings[nameIdxValue]);

			}
			System.out.println();

			if (dexClassDataHeader[i].instanceFieldsSize > 0) {
				System.out.println("It's instance fields info is:");
				System.out
						.println("classType  accessFlag  fieldType  fieldName");
			}
			// instanceField
			for (int m = 0; m < dexClassDataHeader[i].instanceFieldsSize; m++) {
				instanceDexField[m] = new DexField();

				instanceDexField[m].fieldIdxValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				instanceDexField[m].accessFlagsValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				int classIdxValue = byteArraytoInt(fieldsTable[instanceDexField[m].fieldIdxValue].classIdx);
				int typeIdxValue = byteArraytoInt(fieldsTable[instanceDexField[m].fieldIdxValue].typeIdx);
				int nameIdxValue = byteArraytoInt(fieldsTable[instanceDexField[m].fieldIdxValue].nameIdx);

				System.out.println(dexTypes[classIdxValue] + "  "
						+ accessFlags.get(instanceDexField[m].accessFlagsValue)
						+ "  " + dexTypes[typeIdxValue] + "  "
						+ dexStrings[nameIdxValue]);
			}
			System.out.println();

			if (dexClassDataHeader[i].directMethodsSize > 0) {
				System.out.println("It's direct methods info is:");
				System.out
						.println("classType  accessFlag  protoType returnType parameters  methodName");
			}
			// directMethod
			for (int m = 0; m < dexClassDataHeader[i].directMethodsSize; m++) {
				directDexMethod[m] = new DexMethod();

				directDexMethod[m].methodIdxValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				directDexMethod[m].accessFlagsValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				directDexMethod[m].codeOffValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				int classIdxValue = byteArraytoInt(methodsTable[directDexMethod[m].methodIdxValue].classIdx);
				int protoIdxValue = byteArraytoInt(methodsTable[directDexMethod[m].methodIdxValue].protoIdx);
				int nameIdxValue = byteArraytoInt(methodsTable[directDexMethod[m].methodIdxValue].nameIdx);

				System.out.println(dexTypes[classIdxValue] + "  "
						+ accessFlags.get(directDexMethod[m].accessFlagsValue)
						+ "  " + dexProtos[protoIdxValue] + "  "
						+ dexStrings[nameIdxValue]);

			}
			System.out.println();

			if (dexClassDataHeader[i].virualMethodsSize > 0) {
				System.out.println("It's virual methods info is:");
				System.out
						.println("classType  accessFlag  protoType returnType parameters  methodName");
			}
			// virualMethod
			for (int m = 0; m < dexClassDataHeader[i].virualMethodsSize; m++) {
				virualDexMethod[m] = new DexMethod();

				virualDexMethod[m].methodIdxValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				virualDexMethod[m].accessFlagsValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				virualDexMethod[m].codeOffValue = readUnsignedLeb128(Arrays
						.copyOfRange(sourceDEXFileArray, changeOffset
								+ offsetPer, changeOffset + offsetPer + 5));
				offsetPer += unsignedLeb128Size(Arrays.copyOfRange(
						sourceDEXFileArray, changeOffset + offsetPer,
						changeOffset + offsetPer + 5));

				int classIdxValue = byteArraytoInt(methodsTable[virualDexMethod[m].methodIdxValue].classIdx);
				int protoIdxValue = byteArraytoInt(methodsTable[virualDexMethod[m].methodIdxValue].protoIdx);
				int nameIdxValue = byteArraytoInt(methodsTable[virualDexMethod[m].methodIdxValue].nameIdx);

				System.out.println(dexTypes[classIdxValue] + "  "
						+ accessFlags.get(virualDexMethod[m].accessFlagsValue)
						+ "  " + dexProtos[protoIdxValue] + "  "
						+ dexStrings[nameIdxValue]);
			}
			System.out.println();
		}

	}

	/**
	 * byte[]转int 以小端方式存放数据 由于int型占用4个字节，这里只能处理最多4字节的byte数组 success
	 * 
	 * @param bytes
	 * @return
	 */
	public static int byteArraytoInt(byte[] bytes) {
		int length = bytes.length;
		int value = 0;
		for (int i = 0; i < length; i++) {
			int shift = i * 8;
			value += (bytes[i] & 0x000000FF) << shift;
		}
		return value;
	}

	/**
	 * DexHeader结构赋值 success
	 *
	 */
	public static void fillDexHeader(DexHeader dexHeader,
			byte[] sourceDEXFileArray) {
		dexHeader.magic = Arrays.copyOfRange(sourceDEXFileArray, 0, 8);
		dexHeader.checksum = Arrays.copyOfRange(sourceDEXFileArray, 8, 12);
		dexHeader.signature = Arrays.copyOfRange(sourceDEXFileArray, 12, 32);
		dexHeader.file_size = Arrays.copyOfRange(sourceDEXFileArray, 32, 36);
		dexHeader.header_size = Arrays.copyOfRange(sourceDEXFileArray, 36, 40);
		dexHeader.endian_tag = Arrays.copyOfRange(sourceDEXFileArray, 40, 44);
		dexHeader.link_size = Arrays.copyOfRange(sourceDEXFileArray, 44, 48);
		dexHeader.link_off = Arrays.copyOfRange(sourceDEXFileArray, 48, 52);
		dexHeader.map_off = Arrays.copyOfRange(sourceDEXFileArray, 52, 56);
		dexHeader.string_ids_size = Arrays.copyOfRange(sourceDEXFileArray, 56,
				60);
		dexHeader.string_ids_off = Arrays.copyOfRange(sourceDEXFileArray, 60,
				64);
		dexHeader.type_ids_size = Arrays
				.copyOfRange(sourceDEXFileArray, 64, 68);
		dexHeader.type_ids_off = Arrays.copyOfRange(sourceDEXFileArray, 68, 72);
		dexHeader.proto_ids_size = Arrays.copyOfRange(sourceDEXFileArray, 72,
				76);
		dexHeader.proto_ids_off = Arrays
				.copyOfRange(sourceDEXFileArray, 76, 80);
		dexHeader.field_ids_size = Arrays.copyOfRange(sourceDEXFileArray, 80,
				84);
		dexHeader.field_ids_off = Arrays
				.copyOfRange(sourceDEXFileArray, 84, 88);
		dexHeader.method_ids_size = Arrays.copyOfRange(sourceDEXFileArray, 88,
				92);
		dexHeader.method_ids_off = Arrays.copyOfRange(sourceDEXFileArray, 92,
				96);
		dexHeader.class_defs_size = Arrays.copyOfRange(sourceDEXFileArray, 96,
				100);
		dexHeader.class_defs_off = Arrays.copyOfRange(sourceDEXFileArray, 100,
				104);
		dexHeader.data_size = Arrays.copyOfRange(sourceDEXFileArray, 104, 108);
		dexHeader.data_off = Arrays.copyOfRange(sourceDEXFileArray, 108, 112);
	}

	/**
	 * 打印出DexHeader部分的信息 success
	 * 
	 * @param dexHeader
	 */
	public static void printDexHeader(DexHeader dexHeader) {
		System.out.println("The dex header's info is below.");

		try {
			System.out.println("magic:" + new String(dexHeader.magic, "UTF-8"));

			System.out.print("checkSum:");
			for (int i = 0; i < 4; i++) {
				System.out.print(" "
						+ Integer.toHexString(Byte
								.toUnsignedInt(dexHeader.checksum[i])));
			}
			System.out.println();

			System.out.print("signature:");
			for (int i = 0; i < 20; i++) {
				System.out.print(" "
						+ Integer.toHexString(Byte
								.toUnsignedInt(dexHeader.signature[i])));
			}
			System.out.println();

			System.out.println("file_size:"
					+ byteArraytoInt(dexHeader.file_size) + "bytes");
			System.out.println("header_size:"
					+ byteArraytoInt(dexHeader.header_size) + "bytes");

			System.out.print("endian_tag:");
			for (int i = 0; i < 4; i++) {
				System.out.print(" "
						+ Integer.toHexString(Byte
								.toUnsignedInt(dexHeader.endian_tag[i])));
			}
			System.out.println();

			System.out.println("link_size:"
					+ byteArraytoInt(dexHeader.link_size));
			System.out
					.println("link_off:" + byteArraytoInt(dexHeader.link_off));
			System.out.println("map_off:" + byteArraytoInt(dexHeader.map_off));
			System.out.println("string_ids_size:"
					+ byteArraytoInt(dexHeader.string_ids_size));
			System.out.println("string_ids_off:"
					+ byteArraytoInt(dexHeader.string_ids_off));
			System.out.println("type_ids_size:"
					+ byteArraytoInt(dexHeader.type_ids_size));
			System.out.println("type_ids_off:"
					+ byteArraytoInt(dexHeader.type_ids_off));
			System.out.println("proto_ids_size:"
					+ byteArraytoInt(dexHeader.proto_ids_size));
			System.out.println("proto_ids_off:"
					+ byteArraytoInt(dexHeader.proto_ids_off));
			System.out.println("field_ids_size:"
					+ byteArraytoInt(dexHeader.field_ids_size));
			System.out.println("field_ids_off:"
					+ byteArraytoInt(dexHeader.field_ids_off));
			System.out.println("method_ids_size:"
					+ byteArraytoInt(dexHeader.method_ids_size));
			System.out.println("method_ids_off:"
					+ byteArraytoInt(dexHeader.method_ids_off));
			System.out.println("class_defs_size:"
					+ byteArraytoInt(dexHeader.class_defs_size));
			System.out.println("class_defs_off:"
					+ byteArraytoInt(dexHeader.class_defs_off));
			System.out.println("data_size:"
					+ byteArraytoInt(dexHeader.data_size));
			System.out
					.println("data_off:" + byteArraytoInt(dexHeader.data_off));
			System.out.println("\n");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * 以字节方式读取文件 success
	 * 
	 * @param fileName
	 * @return byte[]
	 */
	public static byte[] readFileBytes(File fileName) {
		FileInputStream in;
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int count;
		try {
			in = new FileInputStream(fileName);
			try {
				while ((count = in.read(buffer)) != -1) {
					byteArrayOutputStream.write(buffer, 0, count);
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return byteArrayOutputStream.toByteArray();

		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return null;
	}

	/**
	 * 获得dex文件中所有的字符串 success
	 * 
	 * @param dexStrings
	 *            最终获取的string
	 * @param stringTable
	 *            string在dex文件中的偏移
	 * @param sourceDEXFileArray
	 *            dex文件字节形式
	 */
	public static void getDexStrings(String[] dexStrings,
			DexStringTable[] stringTable, DexHeader dexHeader,
			byte[] sourceDEXFileArray) {
		// 找出dex文件中所有的字符串
		// 字符串使用的是MUTF-8编码，对于一个字符串前面1-5个字节是uleb128编码指明该字符串含有几个字符，紧接着才是真正的utf-8编码
		// 所以对于一个字符串应该先查明uleb128编码使用了几个字符串，
		int numOfStrings = byteArraytoInt(dexHeader.string_ids_size); // 共有多少个字符串
		int offSetOfStringTable = byteArraytoInt(dexHeader.string_ids_off); // DexStringTable的偏移值

		for (int i = 0; i < numOfStrings; i++) { // stringTable中存储着所有字符串的偏移
			stringTable[i] = new DexStringTable(); // 创建一个实例
			stringTable[i].stringDataOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfStringTable + i * 4,
					offSetOfStringTable + i * 4 + 4);
		}

		for (int i = 0; i < numOfStrings; i++) {

			byte[] uleb128StringSizeArray = Arrays.copyOfRange(
					sourceDEXFileArray,
					byteArraytoInt(stringTable[i].stringDataOff),
					byteArraytoInt(stringTable[i].stringDataOff) + 5);
			int uleb128StringSize = unsignedLeb128Size(uleb128StringSizeArray); // 获取uleb128字符编码的长度

			byte[] stringArray = Arrays.copyOfRange(sourceDEXFileArray,
					byteArraytoInt(stringTable[i].stringDataOff)
							+ uleb128StringSize,
					byteArraytoInt(stringTable[i].stringDataOff)
							+ readUnsignedLeb128(uleb128StringSizeArray) + 1);

			try {
				dexStrings[i] = new String(stringArray, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	/**
	 * 获得dex文件中所有的数据类型 success
	 * 
	 * @param dexType
	 * @param dexHeader
	 * @param sourceDEXFileArray
	 */
	public static void getDexTypes(String[] dexTypes, String[] dexStrings,
			DexHeader dexHeader, byte[] sourceDEXFileArray) {
		int numOfTypes = byteArraytoInt(dexHeader.type_ids_size);
		int offSetOfTypeTable = byteArraytoInt(dexHeader.type_ids_off); // DexTypeTable表的偏移值
		for (int i = 0; i < numOfTypes; i++) {
			dexTypes[i] = dexStrings[byteArraytoInt(Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfTypeTable + i * 4,
					offSetOfTypeTable + i * 4 + 4))];
		}
	}

	/**
	 * 获取dex文件中protos声明信息 success
	 * 
	 * @param dexProtos
	 * @param dexStrings
	 * @param dexTyps
	 * @param protosTable
	 * @param dexHeader
	 * @param sourceDEXFileArray
	 */
	public static void getDexProtos(String[] dexProtos, String[] dexStrings,
			String[] dexTyps, DexProtos[] protosTable, DexHeader dexHeader,
			byte[] sourceDEXFileArray) {
		int numOfProtos = byteArraytoInt(dexHeader.proto_ids_size);
		int offSetOfProtoTable = byteArraytoInt(dexHeader.proto_ids_off); // DexStringTable的偏移值
		String tempParameters = new String();
		for (int i = 0; i < numOfProtos; i++) { // stringTable中存储着所有字符串的偏移

			protosTable[i] = new DexProtos(); // 创建一个实例
			protosTable[i].shortIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfProtoTable + i * 12, offSetOfProtoTable + i * 12
							+ 4);
			protosTable[i].returnTypeIdx = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfProtoTable + i * 12 + 4,
					offSetOfProtoTable + i * 12 + 8);
			protosTable[i].parametersOff = Arrays.copyOfRange(
					sourceDEXFileArray, offSetOfProtoTable + i * 12 + 8,
					offSetOfProtoTable + i * 12 + 12);
			// parametersOff为0的情况
			if (byteArraytoInt(protosTable[i].parametersOff) != 0) {
				protosTable[i].sizeArray = Arrays.copyOfRange(
						sourceDEXFileArray,
						byteArraytoInt(protosTable[i].parametersOff),
						byteArraytoInt(protosTable[i].parametersOff) + 4);
				protosTable[i].size = byteArraytoInt(protosTable[i].sizeArray);
				protosTable[i].typeidx = Arrays.copyOfRange(sourceDEXFileArray,
						byteArraytoInt(protosTable[i].parametersOff) + 4,
						byteArraytoInt(protosTable[i].parametersOff) + 4
								+ protosTable[i].size * 2);

				for (int j = 0; j < protosTable[i].size; j++) {
					tempParameters += dexTyps[byteArraytoInt(Arrays
							.copyOfRange(protosTable[i].typeidx, j * 2,
									j * 2 + 2))]
							+ ",";
				}
			}

			dexProtos[i] = dexTyps[byteArraytoInt(protosTable[i].returnTypeIdx)]
					+ " "
					+ dexStrings[byteArraytoInt(protosTable[i].shortIdx)]
					+ " (" + tempParameters + ")";
		}
	}

	/**
	 * 获取dex文件中字段信息 success
	 * 
	 * @param dexFields
	 * @param fieldsTable
	 * @param dexStrings
	 * @param dexTypes
	 * @param dexHeader
	 * @param sourceDEXFileArray
	 */
	public static void getDexFields(String[] dexFields,
			DexFieldTable[] fieldsTable, String[] dexStrings,
			String[] dexTypes, DexHeader dexHeader, byte[] sourceDEXFileArray) {
		int numOfFields = byteArraytoInt(dexHeader.field_ids_size);
		int offSetOfFieldTable = byteArraytoInt(dexHeader.field_ids_off);

		for (int i = 0; i < numOfFields; i++) {
			fieldsTable[i] = new DexFieldTable();
			fieldsTable[i].classIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfFieldTable + i * 8, offSetOfFieldTable + i * 8 + 2);
			fieldsTable[i].typeIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfFieldTable + i * 8 + 2, offSetOfFieldTable + i * 8
							+ 4);
			fieldsTable[i].nameIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfFieldTable + i * 8 + 4, offSetOfFieldTable + i * 8
							+ 8);
			dexFields[i] = dexTypes[byteArraytoInt(fieldsTable[i].classIdx)]
					+ " " + dexTypes[byteArraytoInt(fieldsTable[i].typeIdx)]
					+ " " + dexStrings[byteArraytoInt(fieldsTable[i].nameIdx)];
		}
	}

	/**
	 * 获取dex文件中函数信息 success
	 * 
	 * @param dexMethods
	 * @param methodsTable
	 * @param dexStrings
	 * @param dexTypes
	 * @param protosTable
	 * @param dexHeader
	 * @param sourceDEXFileArray
	 */
	public static void getDexMethods(String[] dexMethods,
			DexMethodTable[] methodsTable, String[] dexStrings,
			String[] dexTypes, DexProtos[] protosTable, DexHeader dexHeader,
			byte[] sourceDEXFileArray) {
		int numOfMethods = byteArraytoInt(dexHeader.method_ids_size);
		int offSetOfMethodTable = byteArraytoInt(dexHeader.method_ids_off);

		for (int i = 0; i < numOfMethods; i++) {
			methodsTable[i] = new DexMethodTable();
			methodsTable[i].classIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfMethodTable + i * 8, offSetOfMethodTable + i * 8
							+ 2);
			methodsTable[i].protoIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfMethodTable + i * 8 + 2, offSetOfMethodTable + i
							* 8 + 4);
			methodsTable[i].nameIdx = Arrays.copyOfRange(sourceDEXFileArray,
					offSetOfMethodTable + i * 8 + 4, offSetOfMethodTable + i
							* 8 + 8);
			dexMethods[i] = dexTypes[byteArraytoInt(methodsTable[i].classIdx)]
					+ " "
					+ dexStrings[byteArraytoInt(protosTable[byteArraytoInt(methodsTable[i].protoIdx)].shortIdx)]
					+ " " + dexStrings[byteArraytoInt(methodsTable[i].nameIdx)];
		}
	}

	/**
	 * ULEB128编码 success
	 * 
	 * @param pStream
	 * @return int
	 */
	public static int readUnsignedLeb128(byte[] pStream) {
		int result = 0;
		int cur = 0;

		result = pStream[0] & 0x7f;
		cur = pStream[0] & 0xff;
		if (cur > 0x7f) {
			result |= (pStream[1] & 0x7f) << 7;
			cur = pStream[1] & 0xff;
			if (cur > 0x7f) {
				result |= (pStream[2] & 0x7f) << 14;
				cur = pStream[2] & 0xff;
				if (cur > 0x7f) {
					result |= (pStream[3] & 0x7f) << 21;
					cur = pStream[3] & 0xff;
					if (cur > 0x7f) {
						result |= (pStream[4] & 0x7f) << 28;
					}
				}
			}
		}
		return result;
	}

	/**
	 * 获取uleb128编码占据的长度
	 * 
	 * @param pStream
	 * @return
	 */
	public static int unsignedLeb128Size(byte[] pStream) {
		int count = 0;
		int cur = 0;
		cur = pStream[0] & 0xff;
		while (cur > 0x7f) {
			count++;
			cur = pStream[count] & 0xff;
		}
		return ++count;
	}

	/**
	 * SLEB128编码
	 * 
	 * @param pStream
	 * @return int
	 */
	public static int readSignedLeb128(byte[] pStream) {
		int result = 0;
		int cur = 0;

		result = pStream[0] & 0x7f;
		cur = pStream[0] & 0xff;
		if (cur < 0x7f) {
			result = (result << 25) >> 25;
		} else {
			cur = pStream[1] & 0xff;
			if (cur < 0x7f) {
				result = ((result | (pStream[1] & 0x7f) << 7) << 18) >> 18;
			} else {
				cur = pStream[2] & 0xff;
				if (cur < 0x7f) {
					result = ((result | (pStream[2] & 0x7f) << 14) << 11) >> 11;
				} else {
					cur = pStream[3] & 0xff;
					if (cur < 0x7f) {
						result = ((result | (pStream[3] & 0x7f) << 21) << 4) >> 4;
					} else {
						result = (result | (pStream[4] & 0x7f) << 28);
					}
				}
			}
		}
		return result;
	}
}
