import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.api_client import get_network_graph


def render_network_graph_page():
    st.header("🌐 Network Investigation Graph")
    st.caption("Visualize endpoint communication powered by FastAPI")

    host_id = st.text_input(
        "Host Filter (optional)",
        placeholder="Host ID",
    )

    if st.button("Load Network Graph", type="primary"):

        try:
            response = get_network_graph(
                host_id=host_id or None,
            )
        except Exception as e:
            st.error(f"Network Graph API error: {e}")
            return

        nodes = response.get("nodes", [])
        edges = response.get("edges", [])

        c1, c2 = st.columns(2)

        c1.metric("Nodes", len(nodes))
        c2.metric("Edges", len(edges))

        st.divider()

        if not nodes:
            st.info("No network graph available.")
            return

        node_df = pd.DataFrame(nodes)
        edge_df = pd.DataFrame(edges)

        st.subheader("Nodes")

        st.dataframe(
            node_df,
            use_container_width=True,
        )

        st.subheader("Connections")

        st.dataframe(
            edge_df,
            use_container_width=True,
        )

        st.divider()

        fig = go.Figure()

        fig.add_trace(
            go.Scatter(
                x=list(range(len(nodes))),
                y=[0] * len(nodes),
                mode="markers+text",
                text=node_df["label"],
                textposition="top center",
                marker=dict(
                    size=18,
                ),
            )
        )

        for i, edge in edge_df.iterrows():

            try:
                src = node_df.index[node_df["id"] == edge["source"]][0]
                dst = node_df.index[node_df["id"] == edge["target"]][0]

                fig.add_trace(
                    go.Scatter(
                        x=[src, dst],
                        y=[0, 0],
                        mode="lines",
                        showlegend=False,
                    )
                )

            except Exception:
                pass

        fig.update_layout(
            height=500,
            title="Network Relationship Graph",
            xaxis=dict(showgrid=False, visible=False),
            yaxis=dict(showgrid=False, visible=False),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

        with st.expander("Raw API Response"):
            st.json(response)