import { Card, CardContent, CardHeader, Grid, Typography } from "@mui/material";
import { IDB } from "./types";
import HeatMap from '@uiw/react-heat-map';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs'
import { DatePicker } from '@mui/x-date-pickers/DatePicker';

const value = [
    { date: '2016/01/11', count: 2, content: 'hello' },
    { date: '2016/08/11', count: 2, content: 'hello' },
  ];

function DbCard(props: {db: IDB}) {
    let {db} = props;
    return (
      <Grid item xs={12}>
        <Card>
          <CardHeader title={db.metadata.name} />
          <CardContent>
            <LocalizationProvider dateAdapter={AdapterDayjs}>
              <DatePicker />
            </LocalizationProvider>
            <HeatMap
                value={value}
                startDate={new Date('2016/01/01')}
                width={600} />
          </CardContent>
        </Card>
      </Grid>
    );
} 

export default DbCard;