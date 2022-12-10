use std::fs::File;
use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::*;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowReader;
use parquet::arrow::ArrowWriter;
use parquet::arrow::ParquetFileArrowReader;
use parquet::arrow::arrow_to_parquet_schema;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;

#[cfg(test)]
mod tests {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    use super::*;

    #[test]
    fn test_round_trip() {
        // Define the schema for our data, which will consist of a
        // timestamp field and a stack trace field
        let schema = Arc::new(Schema::new(vec![
            Field::new("timestamp", DataType::Timestamp(TimeUnit::Millisecond, None), true),
            Field::new("stack_trace", DataType::Binary, true),
        ]));

        let ts_array = TimestampMillisecondArray::from(vec![1, 2]);
        let values: Vec<&[u8]> = vec![b"0", b"1"];
        let stack_array = BinaryArray::from(values);

        // Create a new record batch with the specified schema
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts_array),
                Arc::new(stack_array),
            ],
        ).unwrap();

        // Flush the record batch to disk as a Parquet file
        let props = Arc::new(WriterProperties::builder().build());
        let mut file = File::create("data.parquet").unwrap();

        let to_write = batch;

        let mut writer = ArrowWriter::try_new(&mut file, to_write.schema(), None).unwrap();
        writer.write(&to_write).unwrap();
        writer.close().unwrap();
        drop(file);

        let file = File::open("data.parquet").unwrap();
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(file).unwrap()
            .with_batch_size(1024)
            .build()
            .unwrap();
        let read = reader.next().unwrap().unwrap();

        dbg!(read);

    }
}