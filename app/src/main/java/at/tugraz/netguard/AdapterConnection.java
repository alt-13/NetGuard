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
import java.util.HashSet;

import eu.faircode.netguard.R;
import eu.faircode.netguard.Util;

public class AdapterConnection extends CursorAdapter {
    private int colDaddr;
    private int colDPort;
    private int colTime;
    private int colCipherSuite;
    private int colKeywords;

    private int colorSecure;
    private int colorInsecure;

    public AdapterConnection(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colCipherSuite = cursor.getColumnIndex("cipher_suite");
        colKeywords = cursor.getColumnIndex("keywords");

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorSecure = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorInsecure = tv.data;
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.connection, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        final String daddr = cursor.getString(colDaddr);
        final int dport = cursor.getInt(colDPort);
        final int cipherSuite = cursor.getInt(colCipherSuite);
        final byte[] keywords = cursor.getBlob(colKeywords);
        long time = cursor.getLong(colTime);

        // Get views
        TextView tvTime = view.findViewById(R.id.tvTime);
        final TextView tvDest = view.findViewById(R.id.tvDest);

        // Set values
        tvTime.setText(new SimpleDateFormat("dd.MM HH:mm").format(time));
        tvDest.setText(daddr + (dport > 0 ? "/" + dport : ""));

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

        // default is secure state
        tvDest.setTextColor(colorSecure);

        // on insecure cipher suite set state to insecure
        // cipherSuite is -1 in DB when no HTTPS connection
        if (cipherSuite >= 0 && false/*TODO cipher secure lookup*/)
            tvDest.setTextColor(colorInsecure);

        Object o = ACNUtils.byteArrayToObject(keywords);
        if (o != null && o instanceof HashSet) {
            HashSet<String> keywordsAsHashSet = (HashSet<String>) o;

            // on non empty keywords set state to insecure
            if (!keywordsAsHashSet.isEmpty())
                tvDest.setTextColor(colorInsecure);
        }
    }
}
