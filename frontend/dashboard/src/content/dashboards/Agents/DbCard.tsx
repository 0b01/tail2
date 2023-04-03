import { Card, CardContent, CardHeader, Grid, Typography } from "@mui/material";
import { IDB } from "./types";
import HeatMap from '@uiw/react-heat-map';
import { DateTimePicker, LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs'
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useState } from "react";
import { Dayjs } from "dayjs";

const value = [
    { date: '2016/01/11', count: 2, content: 'hello' },
    { date: '2016/08/11', count: 2, content: 'hello' },
  ];

function DbCard(props: {db: IDB}) {
    let [start, setStartDate] = useState<Dayjs | null>(null);
    let [end, setEndDate] = useState<Dayjs | null>(null);
    let {db} = props;

    var baseURL = window.document.URL;
    const data_url = new URL("/api/calltree", baseURL);
    data_url.search = new URLSearchParams({
        db: db.metadata.name,
        start: (1000*start?.unix()).toString(),
        end: (1000*end?.unix()).toString()}).toString();
    const flamegraph_url = new URL("/flamegraph/app.html", baseURL);
    flamegraph_url.searchParams.append("profileURL", data_url.toString());

    // format the tags into "key: value, key: value, ..."
    let tags_str = Object.entries(db.metadata.tags).map((tag) => `${tag[0]}: ${tag[1]}`).join(", ");
    let title = `${db.metadata.name} (${tags_str})`;

    return (
      <Grid item xs={12}>
        <LocalizationProvider dateAdapter={AdapterDayjs}>
        <Card>
          <CardHeader title={title} />
          <CardContent>
            <DateTimePicker value={start} onChange={(newVal) => setStartDate(newVal)} />
            <DateTimePicker value={end} onChange={(newVal) => setEndDate(newVal)} />
            {/* <HeatMap
                value={value}
                startDate={start?.toDate() || new Date()}
                width={600} /> */}
            <iframe src={flamegraph_url.toString()} width="100%" height="500px"></iframe>
          </CardContent>
        </Card>
        </LocalizationProvider>
      </Grid>
    );
} 

export default DbCard;