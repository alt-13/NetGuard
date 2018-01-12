package at.tugraz.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.content.Context;
import android.content.res.TypedArray;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Build;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.view.ViewCompat;
import android.text.SpannableString;
import android.text.style.UnderlineSpan;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;

import eu.faircode.netguard.R;
import eu.faircode.netguard.Util;

public class AdapterConnection extends CursorAdapter {
    private int colDaddr;
    private int colDPort;
    private int colTime;
    private int colCount;

    private int colorText;
    private int colorOn;
    private int colorOff;

    public AdapterConnection(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colCount = cursor.getColumnIndex("count");

        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.access, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        final String daddr = cursor.getString(colDaddr);
        final int dport = cursor.getInt(colDPort);
        long time = cursor.getLong(colTime);
        int count = cursor.getInt(colCount);

        // Get views
        TextView tvTime = view.findViewById(R.id.tvTime);
        final TextView tvDest = view.findViewById(R.id.tvDest);

        // Set values
        tvTime.setText(new SimpleDateFormat("dd HH:mm").format(time));
        String dest = daddr + (dport > 0 ? "/" + dport : "") + (count > 1 ? " ?" + count : "");
        SpannableString span = new SpannableString(dest);
        span.setSpan(new UnderlineSpan(), 0, dest.length(), 0);
        tvDest.setText(span);

        if (Util.isNumericAddress(daddr))
            new AsyncTask<String, Object, String>() {
                @Override
                protected void onPreExecute() {
                    ViewCompat.setHasTransientState(tvDest, true);
                }

                @Override
                protected String doInBackground(String... args) {
                    try {
                        return InetAddress.getByName(args[0]).getHostName();
                    } catch (UnknownHostException ignored) {
                        return args[0];
                    }
                }

                @Override
                protected void onPostExecute(String addr) {
                    tvDest.setText(addr + (dport > 0 ? "/" + dport : ""));
                    ViewCompat.setHasTransientState(tvDest, false);
                }
            }.execute(daddr);


        tvDest.setTextColor(colorOff);

        //llTraffic.setVisibility(connections > 0 || sent > 0 || received > 0 ? View.VISIBLE : View.GONE);
        //if (connections > 0)
        //    tvConnections.setText(context.getString(R.string.msg_count, connections));
    }
}
